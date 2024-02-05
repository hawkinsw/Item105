use chrono::{prelude::*, Duration};
use clap::Parser;
use clio::ClioPath;
use core::time;
use regex::Regex;
use reqwest::Method;
use rss::extension::ExtensionMap;
use rss::Channel;
use serde::de::Error;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::fmt::Display;
use std::fs::File;
use std::io::{BufReader, Read};
use std::str::FromStr;
use std::thread;
use std::time::SystemTime;
use twitter_v2::data::Tweet;
use twitter_v2::id::IntoNumericId;
use twitter_v2::{authorization::Oauth1aToken, ApiResult};
use url::Url;

fn bearer_from_config(
    request: &reqwest::Request,
    config: &TwitterConfig,
) -> Result<reqwest::header::HeaderValue, Box<dyn std::error::Error>> {
    let token = oauth1::Token::from_parts(
        config.consumer_key.clone(),
        config.consumer_secret.clone(),
        config.access_token.clone(),
        config.access_secret.clone(),
    );
    let method = request.method().as_str();
    let url = {
        let mut url = request.url().clone();
        url.set_query(None);
        url.set_fragment(None);
        url
    };
    let request = request.url().query_pairs().collect::<BTreeSet<_>>();
    oauth1::authorize(method, url, &request, &token, oauth1::HmacSha1)
        .parse()
        .map_err(|_| Item105Errors::InvalidAuthorizationHeader.into())
}

async fn update_bio(
    message: &str,
    configuration: &TwitterConfig,
) -> Result<reqwest::Response, Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder()
        .http1_title_case_headers()
        .use_rustls_tls() // Make sure that we get TLS.
        .build()?;

    let mut request = client
        .request(
            Method::POST,
            Url::parse("https://api.twitter.com/1.1/account/update_profile.json")?,
        )
        .query(&[("description", message)])
        .build()?;
    let authorization_header = bearer_from_config(&request, configuration)?;
    request
        .headers_mut()
        .insert(reqwest::header::AUTHORIZATION, authorization_header);

    client.execute(request).await.or_else(|e| Err(e.into()))
}

#[derive(Deserialize, Debug, Clone)]
struct TwitterConfig {
    pub consumer_key: String,
    pub consumer_secret: String,
    pub access_token: String,
    pub access_secret: String,
}

impl TwitterConfig {
    pub fn config_from_file(file: &mut File) -> Result<Self, TwitterConfigErrors> {
        let mut reader = BufReader::new(file);
        let mut file_contents: String = Default::default();
        let _ = reader.read_to_string(&mut file_contents);

        TryInto::try_into(file_contents)
    }
}

#[derive(Debug)]
pub enum TwitterConfigErrors {
    ParseError,
}

impl TryFrom<String> for TwitterConfig {
    type Error = TwitterConfigErrors;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        serde_json::from_str(raw.as_str()).map_err(|_| TwitterConfigErrors::ParseError)
    }
}

#[test]
fn test_TwitterConfig_config_from_file() {
    let mut file = std::fs::File::open("test_config.json").unwrap();
    if let Ok(config) = TwitterConfig::config_from_file(&mut file) {
        assert!(config.access_secret == "access_secret");
        assert!(config.access_token == "access_token");
        assert!(config.consumer_key == "consumer_key");
        assert!(config.consumer_secret == "consumer_secret");
        return;
    }
    assert!(true == false);
}

async fn tweet(message: &str, configuration: &TwitterConfig) -> ApiResult<Oauth1aToken, Tweet, ()> {
    let token = Oauth1aToken::new(
        configuration.consumer_key.clone(),
        configuration.consumer_secret.clone(),
        configuration.access_token.clone(),
        configuration.access_secret.clone(),
    );
    let api = twitter_v2::TwitterApi::new(token);
    let mut tweet_builder = api.post_tweet();

    tweet_builder.text(message.to_string());
    tweet_builder.send().await
}

async fn update_bio(
    message: &str,
    configuration: &TwitterConfig,
    reply_id: Option<impl IntoNumericId>,
) -> ApiResult<Oauth1aToken, Tweet, ()> {
    let token = Oauth1aToken::new(
        configuration.consumer_key.clone(),
        configuration.consumer_secret.clone(),
        configuration.access_token.clone(),
        configuration.access_secret.clone(),
    );
    let api = twitter_v2::TwitterApi::new(token);
    let mut tweet_builder = api.post_tweet();

    if let Some(reply_id) = reply_id {
        tweet_builder.in_reply_to_tweet_id(reply_id);
    }
    tweet_builder.text(message.to_string());
    tweet_builder.send().await
}

#[tokio::test]
async fn test_update_bio() {
    let mut file = std::fs::File::open("502_config.json").unwrap();
    if let Ok(config) = Item105Config::config_from_file(&mut file) {
        let result = update_bio(
            "This is a test of the update_bio_local method.",
            &config.twitter,
        )
        .await;
        assert!(result.is_ok());
        return;
    }
    assert!(false == true)
}

#[tokio::test]
async fn test_tweet() {
    let mut file = std::fs::File::open("config.json").unwrap();
    if let Ok(config) = TwitterConfig::config_from_file(&mut file) {
        let system_time = SystemTime::now();
        let datetime: DateTime<Utc> = system_time.into();
        let tweet_content = format!(
            "Test, test, test: This bot is alive ... {}",
            datetime.format("%d/%m/%Y %T")
        );
        assert!(tweet(tweet_content.as_str(), &config).await.is_ok());
        return;
    }
    assert!(false == true)
}

async fn synchronous_download(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder()
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
            .send()
            .await?
            .bytes()
            .await?
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

    /// Fire an alert when the filer's Item matches this regular expression.
    #[arg(short, long, value_parser = parse_alert_regular_expression)]
    alert: Regex,
}

fn parse_alert_regular_expression(
    s: &str,
) -> Result<Regex, Box<dyn std::error::Error + Send + Sync + 'static>> {
    s.parse().or(Err(String::into(format!(
        "Could not parse alert to a valid regular expression."
    ))))
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

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // TODO: Make this command-line customizable.
    let period = Duration::minutes(10);
    let mut latest: Option<DateTime<FixedOffset>> = args.start_date;

    let mut twitter_config_file = std::fs::File::open("config.json");
    if !twitter_config_file.is_ok() {
        println!(
            "There was an error opening the twitter configuration file: {:?}",
            twitter_config_file
        );
        return;
    }

    let mut twitter_config_file = twitter_config_file.unwrap();

    let twitter_config = TwitterConfig::config_from_file(&mut twitter_config_file);

    if !twitter_config.is_ok() {
        println!(
            "There was an error parsing the twitter configuration file: {:?}",
            twitter_config
        );
        return;
    }

    let twitter_config = twitter_config.unwrap();

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

        if let Some(bio_content) = config.bio.clone() {
            let bio_content = format!("{} Last update: {:?}", bio_content, now);
            let update_bio_result = update_bio(&bio_content, &config.twitter).await;
            if update_bio_result.is_ok() {
                println!("I updated my bio.");
            } else {
                println!(
                    "There was an error when I tried to update my bio: {:?}",
                    update_bio_result
                );
            }
        }

        match synchronous_download(RSS_URL)
            .await
            .and_then(|atom_string| parse_rss(atom_string))
        {
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
                    .await.or_else(|err| {
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
                                if args.alert.is_match(&recent_form_item) {
                                    println!(
                                        "{} (cik: {}) filed an 8-K update with an Item that matched the search criteria ({}).",
                                        title, cik, args.alert.to_string()
                                    );
                                    let message = format!(
                                        "{} (cik: {}) filed an 8-K update with an Item 1.05",
                                        title, cik
                                    );
                                    let tweet_result = tweet(&message, &twitter_config).await;
                                    if tweet_result.is_ok() {
                                        println!("I tweeted: {}", message);
                                    } else {
                                        println!(
                                            "There was an error when I tried to tweet: {:?}",
                                            tweet_result
                                        );
                                    }
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
