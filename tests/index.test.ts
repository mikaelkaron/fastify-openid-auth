import assert from 'node:assert'
import test from 'node:test'
import * as index from '../src/index'

test('should export plugin as default', () => {
  assert.ok(index.default)
})
test('should export login, logout, plugin, refresh, verify', () => {
  assert.ok(index.openIDLoginHandlerFactory)
  assert.ok(index.openIDLogoutHandlerFactory)
  assert.ok(index.openIDHandlersFactory)
  assert.ok(index.openIDRefreshHandlerFactory)
  assert.ok(index.openIDVerifyHandlerFactory)
})
