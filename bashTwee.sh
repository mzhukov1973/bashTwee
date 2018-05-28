#        ┌───────────────────────────────────────────────────────────────────────────────┐
#        │MIT License                                                                    │
#        │                                                                               │
#        │Copyright (c) 2018 Maxim Zhukov                                                │
#        │                                                                               │
#        │Permission is hereby granted, free of charge, to any person obtaining a copy   │
#        │of this software and associated documentation files (the "Software"), to deal  │
#        │in the Software without restriction, including without limitation the rights   │
#        │to use, copy, modify, merge, publish, distribute, sublicense, and/or sell      │
#        │copies of the Software, and to permit persons to whom the Software is          │
#        │furnished to do so, subject to the following conditions:                       │
#        │                                                                               │
#        │The above copyright notice and this permission notice shall be included in all │
#        │copies or substantial portions of the Software.                                │
#        │                                                                               │
#        │THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR     │
#        │IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,       │
#        │FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE    │
#        │AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER         │
#        │LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,  │
#        │OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE  │
#        │SOFTWARE.                                                                      │
#        └───────────────────────────────────────────────────────────────────────────────┘

CURL="/usr/bin/curl"
GPG="/usr/bin/gpg"
ESED="sed -r"
SECRETS_FILE="bashTweeSecrets.json.gpg"
CONSUMER_KEY=`gpg --quiet --decrypt ./${SECRETS_FILE} | grep '"consumer-key(api-key)"' | grep -o ':[ ]*".*,' | grep -o '".*"' | tr -d '"'`
CONSUMER_SECRET=`gpg --quiet --decrypt ./${SECRETS_FILE} | grep '"consumer-secret(api-secret)"' | grep -o ':[ ]*".*,' | grep -o '".*"' | tr -d '"'`
OWNER=`gpg --quiet --decrypt ./${SECRETS_FILE} | grep '"owner"' | grep -o ':[ ]*".*,' | grep -o '".*"' | tr -d '"'`
OWNER_ID=`gpg --quiet --decrypt ./${SECRETS_FILE} | grep '"owner-id"' | grep -o ':[ ]*".*,' | grep -o '".*"' | tr -d '"'`
ACCESS_TOKEN=`gpg --quiet --decrypt ./${SECRETS_FILE} | grep '"access-token"' | grep -o ':[ ]*".*,' | grep -o '".*"' | tr -d '"'`
ACCESS_TOKEN_SECRET=`gpg --quiet --decrypt ./${SECRETS_FILE} | grep '"access-token-secret"' | grep -o ':[ ]*".*,' | grep -o '".*"' | tr -d '"'`
MY_LANGUAGE="en"
MY_SCREEN_NAME="mzhukov31415dev"
TWEET=$@

echo -e "\e[38;2;100;200;100mCONSUMER_KEY: \e[1;38;2;255;0;0m$CONSUMER_KEY\e[m"
echo -e "\e[38;2;100;200;100mCONSUMER_SECRET: \e[1;38;2;255;0;0m$CONSUMER_SECRET\e[m"
echo -e "\e[38;2;100;200;100mOWNER: \e[1;38;2;255;0;0m$OWNER\e[m"
echo -e "\e[38;2;100;200;100mOWNER_ID: \e[1;38;2;255;0;0m$OWNER_ID\e[m"
echo -e "\e[38;2;100;200;100mACCESS_TOKEN: \e[1;38;2;255;0;0m$ACCESS_TOKEN\e[m"
echo -e "\e[38;2;100;200;100mACCESS_TOKEN_SECRET: \e[1;38;2;255;0;0m$ACCESS_TOKEN_SECRET\e[m"
echo -e "\e[38;2;100;200;100mMY_LANGUAGE: \e[1;38;2;0;255;0m$MY_LANGUAGE\e[m"
echo -e "\e[38;2;100;200;100mMY_SCREEN_NAME: \e[1;38;2;0;255;0m$MY_SCREEN_NAME\e[m"
echo -e "\e[38;2;100;200;100mTWEET: \e[1;38;2;255;255;0m$TWEET\e[m"

#Copied from https://github.com/piroor/tweet.sh/blob/master/tweet.sh:
exist_command() {
  type "$1" > /dev/null 2>&1
}

ensure_available() {
  local fatal_error=0

  if [ "$MY_SCREEN_NAME" = '' ]
  then
    echo -e '\e[31;1mFATAL ERROR:\e[m You need to specify your screen name via variable "MY_SCREEN_NAME".' 1>&2
    fatal_error=1
  fi

  if [ "$MY_LANGUAGE" = '' ]
  then
    echo -e '\e[31;1mFATAL ERROR:\e[m You need to specify your language (like "en") via variable "MY_LANGUAGE".' 1>&2
    fatal_error=1
  fi

  if [ "$CONSUMER_KEY" = '' ]
  then
    echo -e '\e[31;1mFATAL ERROR:\e[m You need to specify a consumer key via variable "CONSUMER_KEY".' 1>&2
    fatal_error=1
  fi

  if [ "$CONSUMER_SECRET" = '' ]
  then
    echo -e '\e[31;1mFATAL ERROR:\e[m You need to specify a consumer secret via variable "CONSUMER_SECRET".' 1>&2
    fatal_error=1
  fi

  if [ "$ACCESS_TOKEN" = '' ]
  then
    echo -e '\e[31;1mFATAL ERROR:\e[m You need to specify an access token via variable "ACCESS_TOKEN".' 1>&2
    fatal_error=1
  fi

  if [ "$ACCESS_TOKEN_SECRET" = '' ]
  then
    echo -e '\e[31;1mFATAL ERROR:\e[m You need to specify an access token secret via variable "ACCESS_TOKEN_SECRET".' 1>&2
    fatal_error=1
  fi

  if ! exist_command nkf
  then
    echo -e '\e[31;1mFATAL ERROR:\e[m A required command "nkf" is missing.' 1>&2
    fatal_error=1
  fi

  if ! exist_command curl
  then
    echo -e '\e[31;1mFATAL ERROR:\e[m A required command "curl" is missing.' 1>&2
    fatal_error=1
  fi

  if ! exist_command openssl
  then
    echo -e '\e[31;1mFATAL ERROR:\e[m A required command "openssl" is missing.' 1>&2
    fatal_error=1
  fi

  if ! exist_command jq
  then
    echo -e '\e[31;1mFATAL ERROR:\e[m A required command "jq" is missing.' 1>&2
    fatal_error=1
  fi

  [ $fatal_error = 1 ] && exit 1
}

check_errors() {
  if echo "$1" | grep '^\[' > /dev/null
  then
    return 0
  fi
  if [ "$(echo "$1" | jq -r '.errors | length')" = '0' ]
  then
    return 0
  else
    return 1
  fi
}

post() {
  ensure_available

  local media_params=''

  local OPTIND OPTARG OPT
  while getopts m: OPT
  do
    case $OPT in
      m )
        media_params="media_ids=$OPTARG"
        shift 2
        ;;
    esac
  done

  local params="$(cat << FIN
status $*
$media_params
FIN
  )"
  local result="$(echo "$params" |
                    call_api POST https://api.twitter.com/1.1/statuses/update.json)"

  echo "$result"
  check_errors "$result"
}

sanitize_secret_params() {
  if [ "$CONSUMER_KEY" = '' ]
  then
    cat
    return 0
  fi
  $ESED -e "s/$CONSUMER_KEY/<***consumer-key***>/g" \
        -e "s/$CONSUMER_SECRET/(***consumer-secret***>/g" \
        -e "s/$ACCESS_TOKEN/<***access-token***>/g" \
        -e "s/$ACCESS_TOKEN_SECRET/<***access-token-secret***>/g"
}

log() {
  [ "$DEBUG" = '' ] && return 0
  if [ $# -eq 0 ]
  then
    cat | sanitize_secret_params 1>&2
  else
    echo "$*" | sanitize_secret_params 1>&2
  fi
}

call_api() {
  local method=$1
  local url=$2
  local file=$3
  local params=''
  if [ ! -t 0 ]
  then
    params="$(cat)"
  fi
  local oauth="$(echo "$params" | generate_oauth_header "$method" "$url")"
  local headers="Authorization: OAuth $oauth"
  params="$(echo "$params" | to_encoded_list)"
  log "METHOD : $method"
  log "URL    : $url"
  log "HEADERS: $headers"
  log "PARAMS : $params"
  local file_params=''
  if [ "$file" != '' ]
  then
    local file_param_name="$(echo "$file" | $ESED 's/=.+$//')"
    local file_path="$(echo "$file" | $ESED 's/^[^=]+=//')"
    file_params="--form $file_param_name=@$file_path"
    log "FILE   : $file_path (as $file_param_name)"
  fi
  local debug_params=''
  if [ "$DEBUG" != '' ]
  then
    debug_params="--verbose"
  fi
  local curl_params
  if [ "$method" = 'POST' ]
  then
    local main_params=''
    if [ "$file_params" = '' ]
    then
      # --data parameter requries any input even if it is blank.
      if [ "$params" = '' ]
      then
        params='""'
      fi
      main_params="--data \"$params\""
    elif [ "$params" != '' ]
    then
      # on the other hand, --form parameter doesn't accept blank input.
      main_params="--form \"$params\""
    fi
    curl_params="--header \"$headers\" \
         --silent \
         $main_params \
         $file_params \
         $debug_params \
         $url"
  else
    curl_params="--get \
         --header \"$headers\" \
         --data \"$params\" \
         --silent \
         --http1.1 \
         $debug_params \
         $url"
  fi
  curl_params="$(echo "$curl_params" | tr -d '\n' | $ESED 's/  +/ /g')"
  log "curl $curl_params"
  # Command line string for logging couldn't be executed directly because
  # quotation marks in the command line will be passed to curl as is.
  # To avoid sending of needless quotation marks, the command line must be
  # executed via "eval".
  if [ "$debug_params" = '' ]
  then
    eval "curl $curl_params"
  else
    # to apply sanitize_secret_params only for stderr, swap stderr and stdout temporally.
    (eval "curl $curl_params" 3>&2 2>&1 1>&3 | sanitize_secret_params) 3>&2 2>&1 1>&3
  fi
}

generate_oauth_header() {
  local method=$1
  local url=$2
  local common_params="$(common_params)"
  local signature=$(cat - <(echo "$common_params") | generate_signature "$method" "$url")
  local header=$(cat <(echo "$common_params") <(echo "oauth_signature $signature") |
    to_encoded_list ',' |
    tr -d '\n')
  echo -n "$header"
  log "HEADER: $header"
}

generate_signature() {
  local method=$1
  local url=$2
  local signature_key="${CONSUMER_SECRET}&${ACCESS_TOKEN_SECRET}"
  local encoded_url="$(echo "$url" | url_encode)"
  local signature_source="${method}&${encoded_url}&$( \
    to_encoded_list |
    url_encode |
    # Remove last extra line-break
    tr -d '\n')"
  log "SIGNATURE SOURCE: $signature_source"
  # generate signature
  local signature=$(echo -n "$signature_source" |
    openssl sha1 -hmac $signature_key -binary |
    openssl base64 |
    tr -d '\n')
  echo -n "$signature"
  log "SIGNATURE: $signature"
}

to_encoded_list() {
  local delimiter="$1"
  [ "$delimiter" = '' ] && delimiter='\&'
  local transformed="$( \
    # sort params by their name
    sort -k 1 -t ' ' |
    # remove blank lines
    grep -v '^\s*$' |
    # "name a b c" => "name%20a%20b%20c"
    url_encode |
    # "name%20a%20b%20c" => "name=a%20b%20c"
    sed 's/%20/=/' |
    # connect lines with the delimiter
    paste -s -d "$delimiter" - |
    # remove last line break
    tr -d '\n')"
  echo "$transformed"
  log "to_encoded_list: $transformed"
}

url_encode() {
  # process per line, because nkf -MQ automatically splits
  # the output string to 72 characters per a line.
  while read -r line
  do
    echo "$line" |
      # convert to MIME quoted printable
      #  W8 => input encoding is UTF-8
      #  MQ => quoted printable
      nkf -W8MQ |
      sed 's/=$//' |
      tr '=' '%' |
      # reunify broken linkes to a line
      paste -s -d '\0' - |
      sed -e 's/%7E/~/g' \
          -e 's/%5F/_/g' \
          -e 's/%2D/-/g' \
          -e 's/%2E/./g'
  done
}


common_params() {
  cat << FIN
oauth_consumer_key $CONSUMER_KEY
oauth_nonce $(date +%s%N)
oauth_signature_method HMAC-SHA1
oauth_timestamp $(date +%s)
oauth_token $ACCESS_TOKEN
oauth_version 1.0
FIN
}

kill_descendants() {
  local target_pid=$1
  local children=$(ps --no-heading --ppid $target_pid -o pid)
  for child in $children
  do
    kill_descendants $child
  done
  if [ $target_pid != $$ ]
  then
    kill $target_pid 2>&1 > /dev/null
  fi
}

post "${TWEET}"
