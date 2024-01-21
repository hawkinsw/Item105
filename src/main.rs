use chrono::{prelude::*, Duration};
use clap::Parser;
use core::time;
use rss::extension::ExtensionMap;
use rss::Channel;
use serde::de::Error;
use serde_json::Value;
use std::str::FromStr;
use std::thread;

fn synchronous_download(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::blocking::Client::builder()
        .http1_title_case_headers()
        .use_rustls_tls() // Make sure that we get TLS.
        .build()?;
    return String::from_utf8(
        client
            .request(reqwest::Method::GET, url)
            .header(
                reqwest::header::USER_AGENT,
                "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
            )
            .send()?
            .bytes()?
            .to_vec(),
    )
    .map_err(Into::into);
}

fn json_parse(value: String) -> Result<Value, Box<dyn std::error::Error>> {
    return Ok(serde_json::from_str::<Value>(value.as_str())?);
}

fn parse_recent_form(json: Value) -> Result<(String, String), Box<dyn std::error::Error>> {
    let filings = json
        .as_object()
        .and_then(|obj| obj.get("filings"))
        .ok_or(serde_json::Error::custom("Could not find filings."))?;
    let recent = filings
        .as_object()
        .and_then(|obj| obj.get("recent"))
        .ok_or(serde_json::Error::custom("Could not find recent"))?;
    let form = recent
        .as_object()
        .and_then(|obj| obj.get("form"))
        .ok_or(serde_json::Error::custom("Could not find form."))?;
    let tyype = form
        .as_array()
        .and_then(|arr| arr.get(0))
        .ok_or(serde_json::Error::custom("Could not find the type."))?;
    let type_string = String::from(tyype.as_str().ok_or(serde_json::Error::custom(
        "Could not convert the form's type to a string.",
    ))?);
    let items = recent
        .as_object()
        .and_then(|obj| obj.get("items"))
        .ok_or(serde_json::Error::custom("Could not find the items."))?;
    let item = items
        .as_array()
        .and_then(|arr| arr.get(0))
        .ok_or(serde_json::Error::custom("Could not find the item."))?;
    let item_string = String::from(item.as_str().ok_or(serde_json::Error::custom(
        "Could not convert the filing's item to a string.",
    ))?);

    return Ok((type_string, item_string));
}

fn parse_rss(atom_string: String) -> Result<Channel, Box<dyn std::error::Error>> {
    Channel::from_str(atom_string.as_str()).map_err(Into::into)
}

fn cik_from_extensions(extensions: &ExtensionMap) -> Option<String> {
    let e = extensions.get("edgar").unwrap();
    let f = e.get("xbrlFiling").unwrap();
    for item in f {
        match item.children().get("cikNumber") {
            Some(cik_number) => return Some(cik_number[0].value()?.to_string()),
            _ => {
                continue;
            }
        }
    }
    None
}

#[derive(Parser, Debug)]
#[command(author, about, long_about = None)]
struct Args {
    /// Skip updates before this date.
    #[arg(short, long, value_parser = parse_cli_start_date)]
    start_date: Option<DateTime<FixedOffset>>,

    /// Enable debug output; specify repeatedly for increasingly detailed output.
    #[arg(short, long, action = clap::ArgAction::Count)]
    debug: u8,
}

fn parse_cli_start_date(
    s: &str,
) -> Result<DateTime<FixedOffset>, Box<dyn std::error::Error + Send + Sync + 'static>> {
    s.parse().or(Err(String::into(format!(
        "Could not parse your input to a valid date."
    ))))
}

static RSS_URL: &str = "https://www.sec.gov/Archives/edgar/usgaap.rss.xml";
static JSON_URL: &str = "https://data.sec.gov/submissions/CIK__CIK__.json";

fn main() {
    let args = Args::parse();

    // TODO: Make this command-line customizable.
    let period = Duration::minutes(10);
    let mut latest: Option<DateTime<FixedOffset>> = args.start_date;

    print!("Checking for new Item 1.05 entries",);

    if let Some(latest) = latest {
        print!(" since {}.", latest);
    }
    println!(".");

    loop {
        let mut processed = 0;
        let now = Local::now().fixed_offset();

        let mut new_latest: Option<DateTime<FixedOffset>> = None;

        println!("It is {:?} ... checking for new entries!", now);

        match synchronous_download(RSS_URL).and_then(|atom_string| parse_rss(atom_string)) {
            Err(err) => {
                println!("{}", err)
            }
            Ok(feed) => {
                for entry in feed.items {
                    let updated = entry
                        .pub_date()
                        .and_then(|v| {
                            DateTime::parse_from_rfc2822(v)
                                .map_or(Some(Local::now().fixed_offset()), |v| Some(v))
                        })
                        .unwrap();

                    if let Some(new_latest_date) = new_latest {
                        if updated > new_latest_date {
                            if args.debug > 0 {
                                println!("Marking new latest as {:?}", new_latest_date);
                            }
                            new_latest = Some(updated)
                        }
                    } else {
                        if args.debug > 0 {
                            println!("This is the first item that we are seeing -- setting the baseline new latest to {:?}", updated);
                        }
                        new_latest = Some(updated)
                    }

                    let title = entry.title().unwrap_or("No Title");
                    let cik = cik_from_extensions(entry.extensions());
                    if cik.is_none() {
                        println!(
                            "Could not gather the cik from RSS entry with title {} ... skipping.",
                            title
                        );
                        continue;
                    }
                    let cik = cik.unwrap();

                    if latest.is_some() && updated <= latest.unwrap() {
                        if args.debug > 0 {
                            println!(
                                "Skipping update from {} from {} that we should have seen before.",
                                title, updated
                            );
                        }
                        continue;
                    }

                    if args.debug > 0 {
                        println!("Processing update from {} from {} ...", title, updated);
                    }

                    processed += 1;

                    // TODO: Seems clunky.
                    let formatted_cik = format!("{:0>10}", cik);
                    let json_url = JSON_URL.to_string().replace("__CIK__", &formatted_cik);

                    let r: Result<(String, String), Box<dyn std::error::Error>> = synchronous_download(&json_url)
                    .or_else(|err| {
                        Err(String::into(format!(
                            "There was an error downloading the JSON data for company with CIK of {}: {}",
                            cik, err
                        )))
                    })
                    .and_then(|json_string| json_parse(json_string)
                    .or_else(|err| {
                        Err(String::into(format!(
                            "There was an error parsing the JSON data for company with CIK of {}: {}",
                            cik, err
                        )))
                    })
                    .and_then(|recent_form| parse_recent_form(recent_form)
                    .or_else(|err| {
                        Err(String::into(format!(
                            "There was an error finding the specifics of the filing from company with CIK of {}: {}",
                            cik, err
                        )))
                    })));

                    match r {
                        Ok((recent_form_type, recent_form_item)) => {
                            if recent_form_type == "8-K" {
                                if args.debug > 0 {
                                    println!("Valid filing posted by {} (cik: {})", title, cik);
                                }
                                if recent_form_item.contains("1.05") {
                                    println!(
                                        "{} (cik: {}) filed an 8-K update with a 1.05 item.",
                                        title, cik
                                    )
                                }
                            }
                        }
                        Err(err) => {
                            println!("{}", err)
                        }
                    }
                    // TODO: Make this command-line customizable.
                    thread::sleep(time::Duration::from_secs(1));
                }
            }
        };

        if args.debug > 0 {
            println!("Updating latest from {:?} to {:?} ...", latest, new_latest);
        }
        latest = new_latest;

        println!("Processed {} entries.", processed);
        println!(
            "Scheduled to process entries again in {:?} minutes.",
            period.num_minutes()
        );
        thread::sleep(period.to_std().unwrap());
    }
}
