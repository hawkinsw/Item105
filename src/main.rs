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
use std::net::IpAddr;
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

#[derive(Deserialize, Debug, Clone)]
pub struct PrometheusConfig {
    ip: IpAddr,
    port: u16,
}

#[derive(Deserialize, Debug, Clone)]
struct Item105Config {
    pub bio: Option<String>,
    pub alert: String,
    pub twitter: TwitterConfig,
    pub prometheus: Option<PrometheusConfig>,
}

impl Item105Config {
    pub fn config_from_file(file: &mut File) -> Result<Self, Item105Errors> {
        let mut reader = BufReader::new(file);
        let mut file_contents: String = Default::default();
        let _ = reader.read_to_string(&mut file_contents);

        TryInto::try_into(file_contents)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item105Errors {
    ParseError,
    InvalidAuthorizationHeader,
}

impl Display for Item105Errors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParseError => {
                write!(f, "There was a parse error.")
            }
            Self::InvalidAuthorizationHeader => {
                write!(f, "Invalid authorization header.")
            }
        }
    }
}

impl StdError for Item105Errors {}

impl TryFrom<String> for Item105Config {
    type Error = Item105Errors;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        serde_json::from_str(raw.as_str())
            .or(Err(Item105Errors::ParseError))
            .and_then(|config: Self| {
                parse_alert_regular_expression(config.alert.clone())
                    .or(Err(Item105Errors::ParseError))
                    .and(Ok(config))
            })
    }
}

#[test]
fn test_Item105Config_config_from_file() {
    let mut file = std::fs::File::open("configs/test.json").unwrap();
    if let Ok(config) = Item105Config::config_from_file(&mut file) {
        assert!(config.twitter.access_secret == "access_secret");
        assert!(config.twitter.access_token == "access_token");
        assert!(config.twitter.consumer_key == "consumer_key");
        assert!(config.twitter.consumer_secret == "consumer_secret");
        assert!(config.alert == "anything");
        assert!(config.bio.unwrap() == "my bio");
        return;
    }
    assert!(true == false);
}

#[test]
fn test_Item105Config_config_from_file_bad_alert() {
    let mut file = std::fs::File::open("configs/test_bad_alert.json").unwrap();
    assert!(
        Item105Config::config_from_file(&mut file).is_err_and(|e| e == Item105Errors::ParseError)
    );
}

#[test]
fn test_Item105Config_config_from_file_no_bio() {
    let mut file = std::fs::File::open("configs/test_no_bio.json").unwrap();
    if let Ok(config) = Item105Config::config_from_file(&mut file) {
        assert!(config.bio.is_none());
        return;
    }
    assert!(false)
}

#[test]
fn test_Item105Config_config_good_prometheus() {
    let mut file = std::fs::File::open("configs/test_good_prometheus.json").unwrap();
    if let Ok(config) = Item105Config::config_from_file(&mut file) {
        if let Some(prometheus) = config.prometheus {
            assert!(prometheus.ip.is_ipv4());
            return;
        }
    }
    assert!(false)
}

#[test]
fn test_Item105Config_config_bad_prometheus_ip() {
    let mut file = std::fs::File::open("configs/test_bad_prometheus.json").unwrap();
    let parse_result = Item105Config::config_from_file(&mut file);
    assert!(parse_result.is_err());
}

async fn tweet(
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

async fn tweet_hello(configuration: &TwitterConfig) -> ApiResult<Oauth1aToken, Tweet, ()> {
    let system_time = SystemTime::now();
    let datetime: DateTime<Utc> = system_time.into();
    let hello_content = format!(
        "Test, test, test: This bot says, 'Hello,' at ... {}",
        datetime.format("%d/%m/%Y %T")
    );
    tweet(hello_content.as_str(), configuration, None::<u64>).await
}

#[tokio::test]
async fn test_tweet() {
    let mut file = std::fs::File::open("502_config.json").unwrap();
    if let Ok(config) = Item105Config::config_from_file(&mut file) {
        let result = tweet_hello(&config.twitter).await;
        if let Ok(result) = result {
            assert!(true)
        } else {
            let error = result.err();
            println!("error: {:?}", error);
            assert!(false);
        }
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
                "SEC Insights - Item502 and Item105 Twitter Bots hawkinwh@ucmail.uc.edu",
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct Filing {
    pub items: String,
    pub form: String,
    pub time: DateTime<FixedOffset>,
}

impl Filing {
    fn new(items: String, form: String, time: DateTime<FixedOffset>) -> Self {
        Filing { items, form, time }
    }
}

fn extract_filings_metadata(json: Value) -> Result<Vec<Filing>, Box<dyn std::error::Error>> {
    let filings = json
        .as_object()
        .and_then(|obj| obj.get("filings"))
        .ok_or(serde_json::Error::custom("Could not find filings."))?;
    let recent = filings
        .as_object()
        .and_then(|obj| obj.get("recent"))
        .ok_or(serde_json::Error::custom("Could not find recent"))?;
    let forms = recent
        .as_object()
        .and_then(|obj| obj.get("form"))
        .and_then(|obj| obj.as_array())
        .ok_or(serde_json::Error::custom("Could not find forms."))?;
    let items = recent
        .as_object()
        .and_then(|obj| obj.get("items"))
        .and_then(|obj| obj.as_array())
        .ok_or(serde_json::Error::custom("Could not find items."))?;
    let times: Vec<DateTime<FixedOffset>> = recent
        .as_object()
        .and_then(|obj| obj.get("acceptanceDateTime"))
        .and_then(|obj| obj.as_array())
        .and_then(|obj| {
            Some(
                obj.iter()
                    .map_while(|raw| {
                        raw.as_str()
                            .and_then(|raw_str| DateTime::parse_from_rfc3339(raw_str).ok())
                    })
                    .collect(),
            )
        })
        .and_then(|obj: Vec<DateTime<FixedOffset>>| {
            Some(
                obj.into_iter()
                    .map(|time| time + Duration::hours(4))
                    .collect(),
            )
        })
        .ok_or(serde_json::Error::custom(
            "Could not find acceptance date/times.",
        ))?;
    if forms.len() != items.len() || items.len() != times.len() {
        return Err(Box::new(serde_json::Error::custom(
            "Corrupt filings JSON: Length of arrays do not match",
        )));
    }

    let mut result: Vec<Filing> = Vec::new();

    for index in 0..forms.len() {
        result.push(Filing::new(
            items[index].to_string(),
            forms[index].to_string(),
            times[index],
        ));
    }
    Ok(result)
}

#[test]
fn test_parse_recent_form_slim() {
    let file = std::fs::File::open("test_data/slim.json").unwrap();
    let raw_value: Result<Value, serde_json::Error> = serde_json::from_reader(file);
    assert!(raw_value.is_ok());
    let extract_result = extract_filings_metadata(raw_value.unwrap());
    assert!(extract_result.is_ok());
    assert!(extract_result.unwrap().len() == 3);
}

#[test]
fn test_parse_recent_form_uneven() {
    let file = std::fs::File::open("test_data/uneven.json").unwrap();
    let raw_value: Result<Value, serde_json::Error> = serde_json::from_reader(file);
    assert!(raw_value.is_ok());
    let extract_result = extract_filings_metadata(raw_value.unwrap());
    assert!(
        extract_result.is_err_and(|err| err.to_string().contains("Length of arrays do not match"))
    );
}

#[test]
fn test_parse_recent_form_filter_by_date() {
    let now: DateTime<Utc> = Local::now().into();
    let file = std::fs::File::open("test_data/slim.json").unwrap();
    let raw_value: Result<Value, serde_json::Error> = serde_json::from_reader(file);
    assert!(raw_value.is_ok());

    let extract_result = extract_filings_metadata(raw_value.unwrap());
    let filtered_result = extract_result
        .unwrap()
        .into_iter()
        .filter(|filing| filing.time > now);
    assert!(filtered_result.collect::<Vec<Filing>>().len() == 1);

    assert!(true);
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

    #[clap(short, long, value_parser = clap::value_parser!(ClioPath).exists())]
    config: ClioPath,

    /// Enable debug output; specify repeatedly for increasingly detailed output.
    #[arg(short, long, action = clap::ArgAction::Count)]
    debug: u8,

    /// Send a hello tweet when the bot starts.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    hello: bool,

    /// Execute in dry-run mode.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    dry: bool,
}

fn parse_alert_regular_expression(
    s: String,
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

    //let mut twitter_config_file = std::fs::File::open("config.json");
    let mut twitter_config_clio = args.config.open().unwrap();
    let twitter_config_file = twitter_config_clio.get_file();
    if !twitter_config_file.is_some() {
        println!(
            "There was an error opening the twitter configuration file: {:?}",
            twitter_config_file
        );
        return;
    }

    let mut twitter_config_file = twitter_config_file.unwrap();

    let config = Item105Config::config_from_file(&mut twitter_config_file);

    if !config.is_ok() {
        println!(
            "There was an error parsing the program configuration file: {:?}",
            config
        );
        return;
    }

    let config = config.unwrap();

    print!("Checking for new 8-k entries",);

    if let Some(latest) = latest {
        print!(" since {}.", latest);
    }
    println!(".");

    if args.hello {
        let tweet_hello_result = tweet_hello(&config.twitter).await;
        if tweet_hello_result.is_ok() {
            println!("I successfully tweeted a hello message as requested.");
        } else {
            let tweet_hello_error = tweet_hello_result.err();
            println!(
                "I failed to tweet a hello message as requested: {:?}",
                tweet_hello_error
            );
        }
    }

    // Safe here because we confirmed during config-file parse above.
    let alert: Regex = config.alert.parse().unwrap();

    loop {
        let mut processed = 0;
        let now = Local::now().fixed_offset();

        let mut new_latest: Option<DateTime<FixedOffset>> = None;

        println!("It is {:?} ... checking for new entries!", now);

        if let Some(bio_content) = config.bio.clone() {
            // Only update the bio if we are not on a dry run!
            if !args.dry {
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
                    let filing_link = entry.link();
                    let cik = cik_from_extensions(entry.extensions());
                    if cik.is_none() {
                        println!(
                            "Could not gather the cik from RSS entry with title {} ... skipping.",
                            title
                        );
                        continue;
                    }
                    let cik = cik.unwrap();

                    if latest.is_none() || updated <= latest.unwrap() {
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

                    let r: Result<Vec<Filing>, Box<dyn std::error::Error>> = synchronous_download(&json_url)
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
                    .and_then(|recent_form| extract_filings_metadata(recent_form)
                    .or_else(|err| {
                        Err(String::into(format!(
                            "There was an error finding the specifics of the filing from company with CIK of {}: {}",
                            cik, err
                        )))
                    })));

                    match r {
                        Ok(filings) => {
                            let filings: Vec<Filing> = filings
                                .into_iter()
                                .filter(|filing| latest.is_some() && filing.time > latest.unwrap())
                                .collect();
                            if args.debug > 0 {
                                println!(
                                    "Found {} new, valid filing(s) posted by {} (cik: {})",
                                    filings.len(),
                                    title,
                                    cik
                                );
                            }
                            for filing in filings {
                                if filing.form == "\"8-K\"".to_string() ||
                                   filing.form == "\"8-K/A\"".to_string() {
                                    if args.debug > 0 {
                                        println!(
                                            "{} posted a(n) {} with items {}",
                                            title,
                                            filing.form.clone(),
                                            filing.items.clone()
                                        );
                                    }
                                    if alert.is_match(&filing.items) {
                                        println!(
                                        "{} (cik: {}) filed an 8-K update with an Item that matched the search criteria ({}).",
                                        title, cik, alert.to_string());

                                        // If we are on a dry run, then skip the remaining steps!
                                        if args.dry {
                                            continue;
                                        }

                                        let message = format!(
                                            "{} (cik: {}) filed an 8-K update with an Item {}",
                                            title,
                                            cik,
                                            alert.to_string()
                                        );
                                        let tweet_result =
                                            tweet(&message, &config.twitter, None::<u64>).await;

                                        if let Ok(tweet_result) = tweet_result {
                                            println!("I tweeted: {}", message);
                                            if let Some(posted_tweet) =
                                                tweet_result.into_payload().data()
                                            {
                                                let result_id = posted_tweet.id;
                                                if let Some(filing_link) = filing_link {
                                                    let followup_message =
                                                        format!("Filing URL: {}", filing_link);
                                                    if let Ok(_) = tweet(
                                                        &followup_message,
                                                        &config.twitter,
                                                        Some(result_id),
                                                    )
                                                    .await
                                                    {
                                                        println!("I posted a reply to the original tweet with the link to the filing.")
                                                    }
                                                }
                                            }
                                        } else {
                                            println!(
                                                "There was an error when I tried to tweet: {:?}",
                                                tweet_result
                                            );
                                        }
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
