Password Have I Been Pwned
==========================

This extension extends the Bolt password check on login to also check Have I Been Pwned API V2. If the password has been used in known security breaches it blocks the login with an appropriate message.

## Config

Please see `/app/config/extensions/passwordhaveibeenpwned.scotteuser.yml`.

## Is my password sent to Have I Been Pwned?

No, this uses API Version 2. The process is as follows:

1. Hash the password
2. Take just the first 5 characters of the hash and make a request to Have I Been Pwned.
3. Have I Been Pwned returns between 300 and 600 possible hashes
4. The extension checks for an exact match in the possible matches.

Troy Hunt explains the process in his documentation [here](https://haveibeenpwned.com/API/v2#SearchingPwnedPasswordsByRange).

## Note

I would appreciate feedback and suggestions to improve this extension as Bolt is new territory for me. Go easy :)

## Disclaimer

This extension is provided 'as is'. You are ultimately responsible for your site security. This extension has been built to assist in providing additional security.