import requests
import random
import os

TIMEOUT_DELAY = 10

CANARY = "ndvyepenbvtidpvyzh.com"

headersToFuzz = {
    "x-forwarded-scheme": "http",
    "x-forwarded-host": CANARY,
    "x-forwarded-proto": "http",
    "x-http-method-override": "POST",
    "x-amz-website-redirect-location": CANARY,
    "x-rewrite-url": CANARY,
    "x-host": CANARY,
    "user-agent": CANARY,
    "handle": CANARY,
    "h0st": CANARY,
    "Transfer-Encoding": CANARY,
    "x-original-url": CANARY,
    "x-original-host": CANARY,
    "x-forwarded-prefix": CANARY,
    "x-amz-server-side-encryption": CANARY,
    "trailer": CANARY,
    "fastly-ssl": CANARY,
    "fastly-host": CANARY,
    "fastly-ff": CANARY,
    "fastly-client-ip": CANARY,
    "content-type": CANARY,
    "api-version": CANARY,
    "acunetix-header": CANARY,
    "accept-version": CANARY
}


def behavior_or_confirmed_message(behaviorOrConfirmed, behaviorType, explicitCache, url, header="default"):

    messageDict = {"REFLECTION": "HEADER REFLECTION",
                   "STATUS": "DIFFERENT STATUS-CODE",
                   "LENGTH": "DIFFERENT RESPONSE LENGTH",
                   "BEHAVIOR": "[INTERESTING BEHAVIOR]",
                   "CONFIRMED": "VULNERABILITY CONFIRMED! |"
                   }

    if header != "default":
        message = f"{messageDict[behaviorOrConfirmed]} {messageDict[behaviorType]} | EXPLICIT CACHE : {explicitCache} | URL: {url} | HEADER : {header}\n"
        print(message)
    else:
        message = f"{messageDict[behaviorOrConfirmed]} PORT {messageDict[behaviorType]} | EXPLICIT CACHE : {explicitCache} | URL: {url} | HEADER : {header}\n"
        print(message)


def canary_in_response(response: requests.Response):
    for val in response.headers.values():
        if CANARY in val:
            return True
    if CANARY in response.text:
        return True

    return False


def use_caching(headers):
    if headers.get("X-Cache-Hits") or headers.get("X-Cache") or headers.get("Age") or headers.get("Cf-Cache-Status") or (headers.get("Cache-Control") and ("public" in headers.get("Cache-Control"))):
        return True
    else:
        return False


def vulnerability_confirmed(responseCandidate: requests.Response, url, randNum, buster):
    try:
        confirmationResponse = requests.get(
            f"{url}?cacheBusterX{randNum}={buster}", allow_redirects=False, timeout=TIMEOUT_DELAY)
    except:
        return False
    if confirmationResponse.status_code == responseCandidate.status_code and confirmationResponse.text == responseCandidate.text:
        if canary_in_response(responseCandidate):
            if canary_in_response(confirmationResponse):
                return True
            else:
                return False
        else:
            return True
    else:
        return False


def base_request(url):
    randNum = str(random.randrange(9999999999999))
    buster = str(random.randrange(9999999999999))
    try:
        response = requests.get(
            f"{url}?cacheBusterX{randNum}={buster}", allow_redirects=False, timeout=TIMEOUT_DELAY)
    except:
        return None

    return response


def port_poisoning_check(url, initialResponse):
    randNum = str(random.randrange(9999999999999))
    buster = str(random.randrange(9999999999999))
    findingState = 0

    host = url.split("://")[1].split("/")[0]
    response = None
    try:
        response = requests.get(f"{url}?cacheBusterX{randNum}={buster}", headers={"Host": f"{host}:8888"}, allow_redirects=False, timeout=TIMEOUT_DELAY)
    except:
        return
    explicitCache = str(use_caching(response.headers)).upper()

    if response.status_code != initialResponse.status_code:
        findingState = 1
        if vulnerability_confirmed(response, url, randNum, buster):
            findingState = 2
            behavior_or_confirmed_message("CONFIRMED", "STATUS", explicitCache, url)
            return True
        else:
            behavior_or_confirmed_message("BEHAVIOR", "STATUS", explicitCache, url)

    elif abs(len(response.text) - len(initialResponse.text)) > 0.25 * len(initialResponse.text):
        findingState = 1
        if vulnerability_confirmed(response, url, randNum, buster):
            findingState = 2
            behavior_or_confirmed_message("CONFIRMED", "LENGTH", explicitCache, url)
            return True
        else:
            behavior_or_confirmed_message("BEHAVIOR", "LENGTH", explicitCache, url)

    if findingState == 1:
        return False


def headers_poisoning_check(url, initialResponse):
    findingState = 0
    for header in headersToFuzz.keys():
        payload = {header: headersToFuzz[header]}
        randNum = str(random.randrange(9999999999999))
        buster = str(random.randrange(9999999999999))
        response = None
        try:
            response = requests.get(f"{url}?cacheBusterX{randNum}={buster}",
                                    headers=payload, allow_redirects=False, timeout=TIMEOUT_DELAY)
        except:
            print("Request error... Skipping the URL.")
            continue
        explicitCache = str(use_caching(response.headers)).upper()

        if canary_in_response(response):
            findingState = 1
            # potential_verbose_message("CANARY", url)
            if vulnerability_confirmed(response, url, randNum, buster):
                findingState = 2
                behavior_or_confirmed_message(
                    "CONFIRMED", "REFLECTION", explicitCache, url, header=header)
                return True
            else:
                # potential_verbose_message("UNSUCCESSFUL", url)
                behavior_or_confirmed_message(
                    "BEHAVIOR", "REFLECTION", explicitCache, url, header=header)

        elif response.status_code != initialResponse.status_code:
            findingState = 1
            # potential_verbose_message("STATUS_CODE", url)
            if vulnerability_confirmed(response, url, randNum, buster):
                findingState = 2
                behavior_or_confirmed_message(
                    "CONFIRMED", "STATUS", explicitCache, url, header=header)
                return True
            else:
                # potential_verbose_message("UNSUCCESSFUL", url)
                behavior_or_confirmed_message(
                    "BEHAVIOR", "STATUS", explicitCache, url, header=header)

        elif abs(len(response.text) - len(initialResponse.text)) > 0.25 * len(initialResponse.text):
            findingState = 1
            # potential_verbose_message("LENGTH", url)
            if vulnerability_confirmed(response, url, randNum, buster):
                findingState = 2
                behavior_or_confirmed_message(
                    "CONFIRMED", "LENGTH", explicitCache, url, header=header)
                return True
            else:
                # potential_verbose_message("UNSUCCESSFUL", url)
                behavior_or_confirmed_message(
                    "BEHAVIOR", "LENGTH", explicitCache, url, header=header)

    if findingState == 1:
        return False


def cache_poisoning_check(url):
    initialResponse = base_request(url)
    if not initialResponse:
        return

    if initialResponse.status_code in (200, 304, 302, 301, 401, 402, 403):
        if headers_poisoning_check(url, initialResponse) or port_poisoning_check(url, initialResponse):
            return True

    return False
