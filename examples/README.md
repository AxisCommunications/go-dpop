# Example Implementation

Working implementation of authorization server, resource server and a client that communicates with them.

Run:

```sh
./run-example.sh
```

This will start 2 servers running on localhost, an authorization server and a resource server.
When the enter key is pressed (this allows the servers to start correctly) the client will be started and attempt to get the resource from the resource server.

The client will create a private `ES256` key and create a proof that will be used to request a bound token from the authorization server.  
The returned bound token will then be sent together with a new bound proof to the resource server, the resource server will then validate the signature of the bound token, the signature of the proof and the binding between them.

If everything is validated successfully the resource server will respond with the resource to the client.
