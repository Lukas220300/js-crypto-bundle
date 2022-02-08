beforeAll(() => {
    console.log('foo')

})

test('test test', () => {
    console.log(window)
    console.log(window.crypto)
    console.log(window.crypto.subtle)
    expect(window.crypto).toBeDefined()
})

test('test test', () => {
    console.log('true2')
    expect(window.crypto.subtle).toBeDefined()
})

