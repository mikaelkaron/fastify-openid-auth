import assert from 'node:assert'
import test from 'node:test'
import type { FastifyReply, FastifyRequest } from 'fastify'
import { resolveParameters } from '../src/utils'

const mockRequest = {} as FastifyRequest
const mockReply = {} as FastifyReply

test('resolveParameters returns object directly', async () => {
  const params = { foo: 'bar' }
  const result = await resolveParameters(params, mockRequest, mockReply)
  assert.deepStrictEqual(result, params)
})

test('resolveParameters calls function and returns result', async () => {
  const paramsFn = () => ({ baz: 'qux' })
  const result = await resolveParameters(paramsFn, mockRequest, mockReply)
  assert.deepStrictEqual(result, { baz: 'qux' })
})

test('resolveParameters awaits promise from function', async () => {
  const paramsFn = async () => ({ async: 'yes' })
  const result = await resolveParameters(paramsFn, mockRequest, mockReply)
  assert.deepStrictEqual(result, { async: 'yes' })
})

test('resolveParameters returns undefined if parameters is undefined', async () => {
  const result = await resolveParameters(undefined, mockRequest, mockReply)
  assert.strictEqual(result, undefined)
})
