Multi-Factor Deterministic Password Generator (MFDPG)

[![GitHub issues](https://img.shields.io/github/issues/multifactor/mfdpg)](https://github.com/multifactor/mfdpg/issues)
[![BSD-3-Clause-Clear](https://img.shields.io/badge/license-BSD--3--Clause--Clear-brightgreen.svg)](https://creativecommons.org/licenses/by-nc-sa/4.0/)

The Multi-Factor Deterministic Password Generator (MFDPG) is a deterministic password generator (DPG) that implements the Multi-Factor Key Derivation Function (MFKDF).
Deterministic password generators (DPGs) have been proposed as a substitute for all forms of password management by applying a cryptographic hash function to a user's master password and the domain name of a website to generate a unique pseudorandom password for each domain.
MFDPG does this, but uses multiple authentication factors as an input, making it less susceptible to brute-force attack.
It also implements unique algorithmic solutions for password policy compliance and revocability.
In doing so, MFDPG has the further effect of progressively upgrading any password-based website to support strong MFA.

#### Getting Started
To get started, clone this repository, then install all of the required dependencies using `npm install`. You can run our unit testing suite with `npm test`. The [/benchmark](/benchmark) directory contains benchmarking code and results. For detailed API documentation, see [DOCS.md](DOCS.md).

#### Working Example
The below working example demonstrates the basic functions of multi-factor authentication, portability, revocation, and password generation based on regular expressions.

```js
// Create new MFDPG instance with two authentication factors
const generator1 = await new MFDPG([
  await mfkdf.setup.factors.password('password'),
  await mfkdf.setup.factors.hotp({ secret: Buffer.from('hello world') })
])
// Create a password for a website using a regular expression
const policy = /([A-Za-z]+[0-9]|[0-9]+[A-Za-z])[A-Za-z0-9]*/
const password1 = await generator1.generate('example.com', policy)
// Revoke the password and try again
await generator1.revoke('example.com')
const password2 = await generator1.generate('example.com', policy)
password1.should.not.equal(password2) // assert -> true
// Save your public parameters and "log out"
const material = generator1.export()

// Log back in using a password and HOTP code
const generator2 = await MFDPG.import(material, {
  password: mfkdf.derive.factors.password('password'),
  hotp: mfkdf.derive.factors.hotp(365287)
})
// Regenerate the same password for the same website
const password3 = await generator2.generate('example.com', policy)
password2.should.equal(password3) // assert -> true
```
