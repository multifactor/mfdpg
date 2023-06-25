Multi-Factor Deterministic Password Generator (MFDPG)

[![GitHub issues](https://img.shields.io/github/issues/multifactor/mfdpg)](https://github.com/multifactor/mfdpg/issues)
[![BSD-3-Clause-Clear](https://img.shields.io/badge/license-BSD--3--Clause--Clear-brightgreen.svg)](https://creativecommons.org/licenses/by-nc-sa/4.0/)

The Multi-Factor Deterministic Password Generator (MFDPG) is a deterministic password generator (DPG) that implements the Multi-Factor Key Derivation Function (MFKDF).
Deterministic password generators (DPGs) have been proposed as a substitute for all forms of password management by applying a cryptographic hash function to a user's master password and the domain name of a website to generate a unique pseudorandom password for each domain.
MFDPG does this, but uses multiple authentication factors as an input, making it less susceptible to brute-force attack.
It also implements unique algorithmic solutions for password policy compliance and revocability.
In doing so, MFDPG has the further effect of progressively upgrading any password-based website to support strong MFA.

#### Getting Started
To get started, clone this repository, then install all of the required dependencies using `npm install`. You can run our unit testing suite with `npm test`.
