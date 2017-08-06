Paddle Webhook Verifier
=======================

A helper class to verify [Paddle.com](https://paddle.com/) webhook calls.

For more information about Paddle webhook verification, see the official documentation
https://www.paddle.com/docs/reference-verifying-webhooks

How to use
----------

Construct the verifier with the text of the public key that Paddle gives you in your settings, and then verify webhook
requests that you receive by passing the verifier the `request.getParameterMap()` from the request.

e.g.

```java
PaddleWebhookVerifier verifier = new PaddleWebhookVerifier("3jiasSIDJojosda/asjdnFJSU...AwEAAQ==");
if (!verifier.verify(request.getParameterMap())) {
	response.sendError(401);
	return;
}
```

Download
--------

This package is available in Maven Central:

    <dependencies>
      <dependency>   
        <groupId>com.xk72</groupId>
        <artifactId>paddle-webhook-verifier</artifactId>
        <version>1.0</version>
      </dependency>
    </dependencies>

Dependencies
------------

This package uses a patched version of [Pherialize](https://github.com/karlvr/pherialize) package, by Klaus Reimer
to perform the PHP serialization required by Paddle. 
