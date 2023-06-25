require('chai').should()
const MFDPG = require('./index.js')
const { suite, test } = require('mocha')

suite('setup', () => {
  test('defaults', async () => {
    const generator = new MFDPG()
    generator.should.be.instanceOf(MFDPG)
  })
})
