use tari_utilities::hex::Hex;
extern crate chrono;
extern crate jsonrpc;
extern crate serde;
use chrono::Local;
use curl::easy::{Auth, Easy, List};
use regex::Regex;
use serde_json::{json, Map, Value};
use std::{
    io::{prelude::*, stdout, Read},
    net::{TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
};

const MONEROD_URL: &str = "http://127.0.0.1:18081";
const MONEROD_USER: &str = "user";
const MONEROD_PASS: &str = "pass";
const USE_AUTH: bool = false;

fn base_curl_auth(curl: &mut Easy) {
    curl.username("user").unwrap();
    curl.password("password").unwrap();
    let mut auth = Auth::new();
    auth.basic(true);
    curl.http_auth(&auth);
}

fn base_curl(len: u64, url: &str, post: bool) -> Easy {
    let mut easy = Easy::new();
    easy.url(url).unwrap();
    let mut list = List::new();
    list.append("'Content-Type: application/json").unwrap();
    easy.http_headers(list).unwrap();
    if USE_AUTH {
        base_curl_auth(&mut easy)
    }
    if post == true {
        easy.post(true).unwrap();
        easy.post_field_size(len).unwrap();
    }
    easy
}

fn do_curl(curl: &mut Easy, request: &[u8]) -> Vec<u8> {
    let mut transfer_data = request.clone();
    let mut data = Vec::new();
    {
        let mut transfer = curl.transfer();
        transfer
            .read_function(|buf| Ok(transfer_data.read(buf).unwrap_or(0)))
            .unwrap();

        transfer
            .write_function(|new_data| {
                data.extend_from_slice(new_data);
                Ok(new_data.len())
            })
            .unwrap();

        transfer.perform().unwrap();
    }
    data
}

fn structure_response(response_data: &[u8]) -> String {
    let header = format!(
        "HTTP/1.1 200 \
         OK\r\nAccept-Ranges:bytes\r\nContent-Length:{}\r\nContent-Type:application/json\r\nServer:Epee-based\r\n\r\n",
        String::from_utf8_lossy(response_data).len()
    );
    format!("{}{}", header, String::from_utf8_lossy(response_data))
}

fn get_url_part(request: &[u8]) -> String {
    let string = String::from_utf8_lossy(&request[..]).to_string();
    let mut split_request = string.lines();
    let first_line = split_request.next().unwrap().to_string();
    let mut iter = first_line.split_whitespace();
    iter.next();
    return iter.next().unwrap().to_string();
}

fn get_request_type(request: &[u8]) -> String {
    let string = String::from_utf8_lossy(&request[..]).to_string();
    let mut split_request = string.lines();
    let first_line = split_request.next().unwrap().to_string();
    let mut iter = first_line.split_whitespace();
    return iter.next().unwrap().to_string();
}

fn get_json(request: &[u8]) -> Option<Vec<u8>> {
    let re = Regex::new(r"\{(.*)\}").unwrap(); // Match text from first '{' to last '}'
    let string = stringify_request(request);
    let caps = re.captures(&string);
    return match caps {
        Some(caps) => {
            match caps.get(0) {
                Some(json) => {
                    let result = json.as_str().as_bytes().to_vec();
                    Some(result)
                },
                None => {
                    // Request was malformed.
                    println!("Malformed Request");
                    None
                },
            }
        },
        None => {
            // Request didn't contain any json.
            println!("No Request");
            println!("Request: {}", string);
            None
        },
    };
}

fn stringify_request(buffer: &[u8]) -> String {
    String::from_utf8_lossy(&buffer).to_string()
}

fn handle_connection(mut stream: TcpStream) {
    let mut buffer = [0; 4096];
    stream.read(&mut buffer).unwrap();

    thread::spawn(move || {
        let request_string = stringify_request(&buffer[..]);
        let request_type = get_request_type(&buffer[..]);
        let url_part = get_url_part(&buffer[..]);

        if request_type.starts_with("GET") {
            // GET requests
            let date = Local::now();
            let url = format!("{}{}", MONEROD_URL, url_part);
            let mut curl = base_curl(0, &url, false);
            println!("Request: {}", request_string);
            let data = do_curl(&mut curl, "".as_bytes());
            let response = structure_response(&data[..]);
            println!("Response: {}", response);
            stream.write(response.as_bytes()).unwrap();
            stream.flush().unwrap();
            println!("{}", date.format("%Y-%m-%d %H:%M:%S"));
        } else if request_type.starts_with("POST") {
            // POST requests
            let json_bytes = get_json(&buffer[..]);
            match json_bytes {
                Some(json) => {
                    let url = format!("{}{}", MONEROD_URL, url_part);
                    let mut curl = base_curl(json.len() as u64, &url, true);
                    println!("Request: {}", request_string);
                    let data = do_curl(&mut curl, &json);
                    let response = structure_response(&data[..]);
                    println!("Response: {}", response);
                    stream.write(response.as_bytes()).unwrap();
                    stream.flush().unwrap();
                },
                None => {},
            }
        } else {
            // Not implemented
            println!("Request neither GET or POST");
            println!("Request: {}", request_string);
        }
    });
}

fn main() {
    let listener = TcpListener::bind("127.0.0.1:7878").unwrap();
        for stream in listener.incoming() {
            println!("Handling Connection");
            let stream = stream.unwrap();
            handle_connection(stream);
        }
}
