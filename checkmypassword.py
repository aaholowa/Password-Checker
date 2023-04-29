import requests  # send HTTP requests
import hashlib
import sys


def api_data(query_char):

    url = 'https://api.pwnedpasswords.com/range/' + \
        str(query_char)  # url for desired website
    resp = requests.get(url)  # status code

    # Status code = 200 means the resource was found and can be used, raise an error if the status code is not 200
    if resp.status_code != 200:
        raise RuntimeError(
            f"Error: Status code of {resp.status_code}, check API")

    return resp


def password_leak_count(hashes, hash_check):
    # create list: first element = hashed string; second element = count (times password has been breached)
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:  # check all results
        if h == hash_check:  # entered password has been breached
            return count
    return 0  # password has not been breached


def api_password_check(password):
    # converts password into hexadecimal string
    sha1password = hashlib.sha1(password.encode('utf8')).hexdigest().upper()
    first5_hash = sha1password[:5]  # store first 5 characters
    remain_hash = sha1password[5:]  # store remaining characters
    # store status code of our hashed password
    response = api_data(first5_hash)
    return password_leak_count(response, remain_hash)


def results(arguments):
    for passwords in arguments:
        count = api_password_check(passwords)
        if count:
            print(
                f"WARNING: Your password: {passwords} was breached {count} times.")
        else:
            print(
                f"SUCCESS: Your password: {passwords} has not been breached.")
    return "Check Complete"


# run only the main file
if __name__ == '__main__':
    # receive unlimited inputs (use txt files fro security)
    sys.exit(results(sys.argv[1:]))
