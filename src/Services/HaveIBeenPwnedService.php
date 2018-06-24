<?php

namespace Bolt\Extension\ScottEuser\PasswordHaveIBeenPwned\Services;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ClientException;

class HaveIBeenPwnedService
{

    /**
     * Get number of times password has been used in a known breach.
     *
     * @param string $password
     * @return int The number of times the password has been used in a known breach.
     */
    public function getPasswordPwnedCount(string $password)
    {

        // Only send the first 5 characters of the hash of the password so
        // Have I Been Pwned remains unaware of the actual password in case
        // it is compromised.
        $sha1 = sha1($password);
        $first_5_of_sha1 = substr($sha1, 0, 5);
        $rest_of_sha1 = strtoupper(substr($sha1, 5));

        // Get the range of hashes match the partial SHA1 and look for full match.
        if ($hashes = $this->getRange($first_5_of_sha1)) {
            if ($match = $this->getHashMatch($hashes, $rest_of_sha1)) {
                // Have I Been pwned API returns HASH:COUNT.
                $match_parts = explode(':', $match);
                return end($match_parts);
            }
        }
        return 0;
    }

    /**
     * Get the range of possible matching hashes from the API.
     *
     * @param string $first_5_of_sha1 The 1st 5 characters of the SHA1 of the password.
     * @return array The possible hash matches.
     */
    protected function getRange($first_5_of_sha1)
    {
        $client = new Client([
          'base_uri' => 'https://api.pwnedpasswords.com',
          'headers'  => [
            'Accept' => 'application/vnd.haveibeenpwned.v2+json',
          ],
        ]);

        try {
            $response = $client->get('/range/' . $first_5_of_sha1);
            if (200 === $response->getStatusCode()) {
                $contents = $response->getBody()->getContents();
                return explode("\n", $contents);
            }
        } catch (ClientException $e) {
            return [];
        }
    }

    /**
     * Look for an exact match in the possible matches returned.
     *
     * @param array $hashes The possible matches the API returned.
     * @param string $rest_of_sha1 The second portion of the sha1 not sent via the API.
     * @return string|bool The matching row or false.
     */
    protected function getHashMatch($hashes, $rest_of_sha1)
    {
        foreach ($hashes as $hash) {
            if (strpos($hash, $rest_of_sha1 . ':') === 0) {
                return $hash;
            }
        }
        return false;
    }
}