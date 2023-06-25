const mfkdf = require('mfkdf')
const { CuckooFilter } = require('bloom-filters')
const { createHash } = require('crypto')
const { argon2id } = require('hash-wasm')
const RandExp = require('randexp')
const rand = require('random-seed')

const MAX_REVOCATIONS = 4096
const TARGET_FP_RATE = 0.0001

class MFDPG {
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

  export () {
    return {
      policy: this.policy,
      filter: this.revocations.saveAsJSON()
    }
  }

  static async import (object, factors) {
    const dpg = new MFDPG()
    dpg.revocations = CuckooFilter.fromJSON(object.filter)
    const derive = await mfkdf.derive.key(object.policy, factors)
    dpg.policy = derive.policy
    dpg.key = derive.key
    return dpg
  }

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

  check (hash) {
    return this.revocations.has(hash)
  }

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
