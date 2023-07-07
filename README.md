# @avanio/jwt-util

This JWT utility is a simple tool to help verify JWT symmetric and asymmetric tokens.

## Main features

### IssuerManager

Manages multiple JWT issuers (symmetric and asymmetric) and can be used to get issuer key string or buffer.
This is easy to add if already have valdation in plave for JWT tokens. (requires iss and kid to exists in token)

### JwtManager

Wraps IssuerManager and can be used to verify JWT tokens.

### Examples

Simple symmetric issuer

```typescript
const privateKeyIssuer = new SymmetricIssuer(['http://localhost:8080']);
privateKeyIssuer.add('01', 'some-very-long-secret');

const issuerManager = new IssuerManager();
issuerManager.add(privateKeyIssuer);

await issuerManager.get('http://localhost:8080', '01'); // returns 'some-very-long-secret'
```

Azure multitenant issuer with one allowed tenant and JwtManager

```typescript
const jwt = new JwtManager(new IssuerManager([new JwtAzureMultitenantTokenIssuer({allowedIssuers: [`https://sts.windows.net/${process.env.AZ_TENANT_ID}/`]})]));
// validate with jwt manager
const {isCached, body} = await jwt.verify(token);
```
