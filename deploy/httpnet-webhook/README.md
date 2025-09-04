# Access

The webhook reads the secret from the namespace in which it is running or in which the certificate is requested.
Make sure that the service account has the required permissions.
By default, the permission to read secrets in the same namespace is granted.
