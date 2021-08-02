# HashingProject
To do:
1. Parse the Event-Signature header to get {signature}
2. Using the HMACSHA256 algorithm and a special key, hash the model
3. Compare the received hash with the one taken from {signature}
4. If the hashes match, send the status 200, if not - 400
