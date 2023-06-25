const MFDPG = require('../index.js')
const mfkdf = require('mfkdf')
const fs = require('fs')

const ROUNDS = 100;

(async () => {
  const results = []

  for (let i = 0; i < ROUNDS; i++) {
    // Create a new MFDPG instance with three factors.
    var start = performance.now()
    const generator1 = await new MFDPG([
      await mfkdf.setup.factors.password('password'),
      await mfkdf.setup.factors.hotp({ secret: Buffer.from('hello world') }),
      await mfkdf.setup.factors.uuid({ uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' })
    ])
    const t1 = performance.now() - start

    // Export the public parameters as a string.
    start = performance.now()
    const material = JSON.stringify(generator1.export())
    const t2 = performance.now() - start

    // Reload the MFDPG instance using the same three factors.
    start = performance.now()
    const generator2 = await MFDPG.import(JSON.parse(material), {
      password: mfkdf.derive.factors.password('password'),
      hotp: mfkdf.derive.factors.hotp(365287),
      uuid: mfkdf.derive.factors.uuid('9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d')
    })
    const t3 = performance.now() - start

    // Generate a password for a service using a regular policy.
    start = performance.now()
    const policy = /([A-Za-z]+[0-9]|[0-9]+[A-Za-z])[A-Za-z0-9]*/
    const password = await generator2.generate('example.com', policy)
    const t4 = performance.now() - start

    // Revoke the newly generated password.
    start = performance.now()
    await generator2.revoke('example.com')
    const t5 = performance.now() - start

    const result = [t1, t2, t3, t4, t5]
    results.push(result)
    console.log(i, result)
  }

  fs.writeFileSync('./results.json', JSON.stringify(results))
})()
