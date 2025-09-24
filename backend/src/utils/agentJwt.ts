import jwt from 'jsonwebtoken';

export interface AgentAuthClaims {
  sub: string;
  orgId: string;
  scope: string[];
  iat: number;
  exp: number;
}

const DEFAULT_PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCbgpvU1Snd9/2i
sAAgUNjFKI5gvEOmqsfLhOeOK7SDFayYc97Qk2fDuotF/3l63c73S0NgdmO96G0L
m+19aQnL2DNORdG7m6VFrgqsXl7cnbEdbV/5UtmMVV0jymKZLw5xZyWQxW339K9a
xre86MDTSEAVMJng5OiGLQcrx1lu6w5PxeSFR1LCVnlv4PSGdpQTW3JTHh9YMK/2
InRFLMLIw4PzfuVkrNHETdOXiUBZdoRjWw9MgZidsSZ1BfLT2G9dB9jLDnPsZoES
mRf70qHCjdUOSGwUCk7Pob/vtezaMfAks2EafouSpon2KgbfbGHCjxB8Oe1cwTio
kwxtyk7ZAgMBAAECggEAAI2mJN9Pwnmlptq0hXqR0W8LpEOwL/N1V6Ay4wxKUo15
/MR7boOiKw9y93kBF3+hf9EtqCETS7eWpVwHFw9heZcCUAjio86bNo/WuTyeq/gM
2+5fUAtLrSqcm2VD9RbF4+MaxRDRvAjGPswm9ejKL+uBytSLKMswIM2kShe/SbzA
pOlyf99QdLWLN6OhFH1qp+/Od4MKprg7Ze3bvO6MqFEEvSOR1Pjyrj11TcbbatNI
UH6C3at5abJZgOXavxYKOzAdn1gghfSKf24OgErxqEiBwUYvYhxla1ELPr28DFrt
9owiWYq8Jppmp6jgBsWGVS1Sgum3KuSP/seQ1o9/4QKBgQDYZTrVD4BJCW2trdzb
USrBoFJm+9RiZQcCVdMcsBc0C2y1pyt6ZAsb+VqKUPCEWocmzrsIsrhsbqrXzrob
Mb7gfM3/JfdEWdAvvZzBMcP6RTFTkz8/xWa0cI05Lno28NWGeHQBQPtYKH5Xs6P7
ekFkP5sCLALCMv5BVmwZe4TT+QKBgQC3+Llj0pkQtaFe0aAMkNniVIuSEq2SOdKH
61WbwXVP7nCWQi6ui1kF7pw0tmUTBFoCljjSVcgd0GN3HcHKoOQce8fm6QUadmJu
Ha3ZJd9LMmVAVB+kqMpdCF4h2PylSxtzplICM+fxcWDJqD6HKFBsubVOK3kFhNjt
bxe9HOpJ4QKBgFJCgQ/XOawKAoCAVDGm9DrwyAJP/td8kiKIH52LLvbg1O1k4/k9
qJ90tb9Yr2WQyEmvUpgm4EaP9y/cbRDDY00RBHnWo91+ys4rJTinw1kTDoI3ulZy
ou06z+SJz3mtKW5ZwbdsTV+g3Q5XwqFpQwxpxXIY6t+J5O9Pe/5f3wl5AoGBAJJF
jMlEaXTypKIqE5HKHaKpS+tRNHX9yVlOEFvtniN2VkfxyQH4Q0jHJaV3m7daD2Ld
I8KAd8LUrDDKFQnRkGzhMdhzTx5yH+KjcFUlmntET2KtQBeAKJ19iLJqvr2BkQsL
o0qjEHhUh/rt7QEzWXaI1RGY2Pk9XeiyGnK/KbyhAoGAH7gfM6ijBD+OPQPeWh0i
OwHJ3CtCn301X51vT10Cwspq27OHqPOsyT7LNTmD0bKjKgcBuduWpqUiKEeRw4Y/
ZZfUOx0Cwrb0z/KpOjDo6rCCh/MisKsInyFceVTzB9BIQa2YWQ3y+WUIOlxeQmdQ
iRW/YINh+tfzWNc3CvVMLwc=
-----END PRIVATE KEY-----`;

const DEFAULT_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm4Kb1NUp3ff9orAAIFDY
xSiOYLxDpqrHy4Tnjiu0gxWsmHPe0JNnw7qLRf95et3O90tDYHZjvehtC5vtfWkJ
y9gzTkXRu5ulRa4KrF5e3J2xHW1f+VLZjFVdI8pimS8OcWclkMVt9/SvWsa3vOjA
00hAFTCZ4OTohi0HK8dZbusOT8XkhUdSwlZ5b+D0hnaUE1tyUx4fWDCv9iJ0RSzC
yMOD837lZKzRxE3Tl4lAWXaEY1sPTIGYnbEmdQXy09hvXQfYyw5z7GaBEpkX+9Kh
wo3VDkhsFApOz6G/77Xs2jHwJLNhGn6LkqaJ9ioG32xhwo8QfDntXME4qJMMbcpO
2QIDAQAB
-----END PUBLIC KEY-----`;

const privateKey = process.env.AGENT_JWT_PRIVATE_KEY || DEFAULT_PRIVATE_KEY;
const publicKey = process.env.AGENT_JWT_PUBLIC_KEY || DEFAULT_PUBLIC_KEY;
const tokenTtlSeconds = parseInt(process.env.AGENT_JWT_TTL_SECONDS || '1800', 10);

export const signAgentAccessToken = (
  agentId: string,
  orgId: string,
  scope: string[] = ['jobs:read', 'jobs:write']
): { token: string; expiresIn: number } => {
  const now = Math.floor(Date.now() / 1000);
  const payload: AgentAuthClaims = {
    sub: agentId,
    orgId,
    scope,
    iat: now,
    exp: now + tokenTtlSeconds,
  };

  const token = jwt.sign(payload, privateKey, { algorithm: 'RS256' });
  return { token, expiresIn: tokenTtlSeconds };
};

export const verifyAgentAccessToken = (token: string): AgentAuthClaims => {
  return jwt.verify(token, publicKey, { algorithms: ['RS256'] }) as AgentAuthClaims;
};
