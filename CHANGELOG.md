# [4.1.0](https://github.com/mikaelkaron/fastify-openid-auth/compare/v4.0.2...v4.1.0) (2022-09-30)


### Features

* Pass around `TokenSetParameters` instead of `TokenSet` as it's an interface ([4c44e0c](https://github.com/mikaelkaron/fastify-openid-auth/commit/4c44e0cf1067139d542ce8fb933485b6348a36d8))

## [4.0.2](https://github.com/mikaelkaron/fastify-openid-auth/compare/v4.0.1...v4.0.2) (2022-09-26)


### Bug Fixes

* update fastify version plugin annotation to 4.x ([0fc2427](https://github.com/mikaelkaron/fastify-openid-auth/commit/0fc2427331f74f1646c1ec8c35ce6f5c647a4ef8))

## [4.0.1](https://github.com/mikaelkaron/fastify-openid-auth/compare/v4.0.0...v4.0.1) (2022-09-26)


### Bug Fixes

* make `FastifyRequest.session` compatible with `@fastify/secure-session` ([8ed15c9](https://github.com/mikaelkaron/fastify-openid-auth/commit/8ed15c9f495583398b784316826aad157cb55517))

# [4.0.0](https://github.com/mikaelkaron/fastify-openid-auth/compare/v3.0.0...v4.0.0) (2022-09-26)


### Bug Fixes

* auto-fix eslint ([9a5bfa8](https://github.com/mikaelkaron/fastify-openid-auth/commit/9a5bfa82db5f0d201f7dc54242a54cf51f9574d9))


### Features

* bump deps ([e15e322](https://github.com/mikaelkaron/fastify-openid-auth/commit/e15e32283c3a1f50c239c1a2dbe7c9d4d8245e66))


### BREAKING CHANGES

* This bumps `fastify@4`

# [3.0.0](https://github.com/mikaelkaron/fastify-openid-auth/compare/v2.1.0...v3.0.0) (2022-03-01)


### Code Refactoring

* simplify login code ([5b5e1f8](https://github.com/mikaelkaron/fastify-openid-auth/commit/5b5e1f8502382b362efab04e74b24e05963b2c23))


### Features

* remove dynamic factories ([b30653b](https://github.com/mikaelkaron/fastify-openid-auth/commit/b30653b00d2c33745fc8f51201711575f99310ee))
* use `fastify-error` for plugin errors ([df1ccf9](https://github.com/mikaelkaron/fastify-openid-auth/commit/df1ccf930a6be499105d98d40236c2854da31b6a))


### BREAKING CHANGES

* `OpenIDLoginHandlerOptions.params` is now `OpenIDLoginHandlerOptions.parameters`
* Removed outer factories, resulting in `handlerFactory() => handler` is now just `handler`.

# [2.1.0](https://github.com/mikaelkaron/fastify-openid-auth/compare/v2.0.0...v2.1.0) (2022-02-22)


### Features

* separate plugin from index ([bf9d76d](https://github.com/mikaelkaron/fastify-openid-auth/commit/bf9d76d93e06e14cb7514e438fe5538d17a61550))

# [2.0.0](https://github.com/mikaelkaron/fastify-openid-auth/compare/v1.0.0...v2.0.0) (2022-02-22)


### Features

* separate auth factories into individual files ([3a152ad](https://github.com/mikaelkaron/fastify-openid-auth/commit/3a152adb421047f76df78d0c2b573a0fdb984835))


### BREAKING CHANGES

* read/write no longer gets the client as an argument

# 1.0.0 (2022-02-10)


### Features

* initial code ([033526d](https://github.com/mikaelkaron/fastify-openid-auth/commit/033526d6a0a45a39c52d0ae82ed6b2744c03feb3))