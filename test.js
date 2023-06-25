/* eslint-disable no-unused-expressions */
require('chai').should()
const MFDPG = require('./index.js')
const mfkdf = require('mfkdf')
const { suite, test } = require('mocha')

suite('mfdpg', () => {
  test('setup', async () => {
    const generator = await new MFDPG([
      await mfkdf.setup.factors.password('password')
    ])
    generator.should.be.instanceOf(MFDPG)
  })

  test('portability', async () => {
    const generator1 = await new MFDPG([
      await mfkdf.setup.factors.password('password')
    ])
    const material = generator1.export()
    const generator2 = await MFDPG.import(material, {
      password: mfkdf.derive.factors.password('password')
    })
    generator1.key.toString('hex').should.equal(generator2.key.toString('hex'))
  })

  test('multi-factor-authentication', async () => {
    const generator1 = await new MFDPG([
      await mfkdf.setup.factors.password('password'),
      await mfkdf.setup.factors.hotp({ secret: Buffer.from('hello world') }),
      await mfkdf.setup.factors.uuid({ uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' })
    ])
    const material = generator1.export()
    const generator2 = await MFDPG.import(material, {
      password: mfkdf.derive.factors.password('password'),
      hotp: mfkdf.derive.factors.hotp(365287),
      uuid: mfkdf.derive.factors.uuid('9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d')
    })
    generator1.key.toString('hex').should.equal(generator2.key.toString('hex'))
  })

  test('full-example', async () => {
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
  })
})

suite('correctness', () => {
  test('basic-test', async () => {
    const generator = await new MFDPG([
      await mfkdf.setup.factors.password('password')
    ])
    const password1 = await generator.generate('example.com', /[a-zA-Z]{6,10}/)
    const password2 = await generator.generate('example.com', /[a-zA-Z]{6,10}/)
    password1.should.equal(password2)
  })

  test('full-test', async () => {
    const generator1 = await new MFDPG([
      await mfkdf.setup.factors.password('password')
    ])
    const password1 = await generator1.generate('example.com', /[a-zA-Z]{6,10}/)

    const material = generator1.export()
    const generator2 = await MFDPG.import(material, {
      password: mfkdf.derive.factors.password('password')
    })
    const password2 = await generator2.generate('example.com', /[a-zA-Z]{6,10}/)

    password1.should.equal(password2)
  })
})

suite('safety', () => {
  test('basic-test', async () => {
    const generator1 = await new MFDPG([
      await mfkdf.setup.factors.password('password1')
    ])
    const generator2 = await new MFDPG([
      await mfkdf.setup.factors.password('password2')
    ])
    const password1 = await generator1.generate('example.com', /[a-zA-Z]{6,10}/)
    const password2 = await generator2.generate('example.com', /[a-zA-Z]{6,10}/)
    password1.should.not.equal(password2)
  })

  test('full-test', async () => {
    const generator1 = await new MFDPG([
      await mfkdf.setup.factors.password('password1')
    ])
    const password1 = await generator1.generate('example.com', /[a-zA-Z]{6,10}/)

    const material = generator1.export()
    const generator2 = await MFDPG.import(material, {
      password: mfkdf.derive.factors.password('password2')
    })
    const password2 = await generator2.generate('example.com', /[a-zA-Z]{6,10}/)

    password1.should.not.equal(password2)
  })
})

suite('compatibility', () => {
  test('basic-policy', async () => {
    const generator = await new MFDPG([
      await mfkdf.setup.factors.password('password')
    ])
    const password = await generator.generate('example.com', /[a-zA-Z]{6,10}/)
    password.length.should.be.above(5)
    password.length.should.be.below(11)
  })

  test('custom-policy', async () => {
    const generator = await new MFDPG([
      await mfkdf.setup.factors.password('password')
    ])
    const regex = /([A-Za-z]+[0-9]|[0-9]+[A-Za-z])[A-Za-z0-9]*/
    const password = await generator.generate('example.com', regex)
    regex.test(password).should.be.true
  })
})

suite('revocation', () => {
  test('cuckoo-filter', async () => {
    const generator = await new MFDPG([
      await mfkdf.setup.factors.password('password')
    ])
    generator.check('hello').should.be.false
    generator.revokeKey('hello')
    generator.check('hello').should.be.true
  })

  test('revocability', async () => {
    const generator = await new MFDPG([
      await mfkdf.setup.factors.password('password')
    ])
    const password1 = await generator.generate('example.com', /[a-zA-Z]{6,10}/)
    await generator.revoke('example.com')
    const password2 = await generator.generate('example.com', /[a-zA-Z]{6,10}/)
    password1.should.not.equal(password2)
  })
})
