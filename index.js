/**
 * @file Multi-Factor Deterministic Password Generator (MFDPG)
 * @copyright Multifactor 2023
 */

const mfkdf = require('mfkdf')
const { CuckooFilter } = require('bloom-filters')
const { createHash } = require('crypto')
const { argon2id } = require('hash-wasm')
const RandExp = require('randexp')
const rand = require('random-seed')

const MAX_REVOCATIONS = 4096
const TARGET_FP_RATE = 0.0001

/**
 * An instance of a Multi-Factor Deterministic Password Generator (MFDPG).
 *
 * @typicalname mfdpg
 */

class MFDPG {
  /**
   * Create a brand new MFDPG instance from a series of authentication factors.
   *
   * @param {Array.<MFKDFFactor>} factors - Set of factors for this key.
   * @returns {MFDPG} The newly created MFDPG instance.
   */
  constructor (factors) {
    if (!factors) return

    return new Promise((resolve, reject) => {
      mfkdf.setup.key(factors, {
        size: 16,
        kdf: 'hkdf'
      }).then((setup) => {
        this.policy = setup.policy
        this.revocations = CuckooFilter.create(MAX_REVOCATIONS, TARGET_FP_RATE)
        this.key = setup.key
        const key = this.key.toString('hex')
        for (let i = 0; i < MAX_REVOCATIONS; i++) {
          const hash = createHash('sha256').update(key + i).digest('base64')
          this.revocations.add(hash)
        }
        resolve(this)
      })
    })
  }

  /**
   * Export this MFDPG instance for future use.
   *
   * @returns {Object} The exported public parameters from this MFDPG instance.
   */
  export () {
    return {
      policy: this.policy,
      filter: this.revocations.saveAsJSON()
    }
  }

  /**
   * Create an MFDPG instance from a previously exported instance.
   *
   * @param {Object} object - The previously exported public parameters.
   * @param {Object} factors - The MFKDF factors for recovering the key.
   * @returns {MFDPG} The imported MFDPG instance.
   */
  static async import (object, factors) {
    const dpg = new MFDPG()
    dpg.revocations = CuckooFilter.fromJSON(object.filter)
    const derive = await mfkdf.derive.key(object.policy, factors)
    dpg.policy = derive.policy
    dpg.key = derive.key
    return dpg
  }

  /**
   * Directly add a hashable object to the Cuckoo filter.
   * Removes a fictitious entry to keep the number of entries constant.
   *
   * @param {HashableInput} hash - The object to hash and add to the filter.
   */
  revokeKey (hash) {
    this.revocations.add(hash)
    const key = this.key.toString('hex')
    for (let i = 0; i < MAX_REVOCATIONS; i++) {
      const hash = createHash('sha256').update(key + i).digest('base64')
      if (this.revocations.has(hash)) {
        this.revocations.remove(hash)
        return
      }
    }
  }

  /**
   * Check whether a hashable object is in the Cuckoo filter.
   *
   * @param {HashableInput} hash - The object to hash and check.
   * @returns {Boolean} Whether the hash might be in the filter.
   */
  check (hash) {
    return this.revocations.has(hash)
  }

  /**
   * Add a service to the revocation list using its domain name.
   *
   * @param {string} domain - The domain name of the service to revoke.
   */
  async revoke (domain) {
    let counter = 0
    let preimage
    do {
      counter++
      preimage = await argon2id({
        password: domain + counter,
        salt: this.key,
        parallelism: 1,
        iterations: 2,
        memorySize: 24576,
        hashLength: 32,
        outputType: 'hex'
      })
    } while (this.check(preimage))
    this.revokeKey(preimage)
  }

  /**
   * Generate a password for a given service.
   *
   * @param {string} domain - The domain name of the service.
   * @param {RegExp} regex - The password policy of the service.
   * @returns {string} The generated password for the target service.
   */
  async generate (domain, regex) {
    let counter = 0
    let preimage
    do {
      counter++
      preimage = await argon2id({
        password: domain + counter,
        salt: this.key,
        parallelism: 1,
        iterations: 2,
        memorySize: 24576,
        hashLength: 32,
        outputType: 'hex'
      })
    } while (this.check(preimage))
    const dfa = new RandExp(regex)
    const rng = rand.create(preimage)
    dfa.randInt = rng.intBetween
    return dfa.gen()
  }
}

module.exports = MFDPG
