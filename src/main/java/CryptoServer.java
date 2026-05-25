import io.javalin.Javalin;

public class CryptoServer {
    public static void main(String[] args) {
        
        // Start Server
        Javalin app = Javalin.create(config -> {
            config.staticFiles.add("/public");
        }).start(7070);

        System.out.println("Server started! Open http://localhost:7070 in your browser.");

        // Receive data from the HTML form
        app.post("/api/process", ctx -> {
            try {
                String inputText = ctx.formParam("inputText");
                String action = ctx.formParam("action");
                String algorithm = ctx.formParam("algorithm");
                String secretKey = ctx.formParam("secretKey");
                String salt = ctx.formParam("salt");

                String result = "";

                // Route to the correct Java Crypto logic
                switch (action) {
                  case "encrypt":
    if (algorithm.equals("RSA")) {
        String cipherText = CryptoOperations.encryptRSA(inputText);
        result = "=== ENCRYPTION SUCCESSFUL ===\n" +
                 "Algorithm: RSA (Asymmetric)\n" +
                 "Key Used: [Auto-Generated RSA Public Key stored in memory]\n\n" +
                 "Ciphertext:\n" + cipherText;
    } else {
        // Enforce that the user provides a key for symmetric encryption
        if (secretKey == null || secretKey.isEmpty()) {
            result = "Error: You must enter or generate a Secret Key for " + algorithm + "!";
        } else {
            String cipherText = CryptoOperations.encryptSymmetric(algorithm, inputText, secretKey);
            result = "=== ENCRYPTION SUCCESSFUL ===\n" +
                     "Algorithm: " + algorithm + " (Symmetric)\n" +
                     "Key Used: " + secretKey + "\n\n" +
                     "Ciphertext:\n" + cipherText;
        }
    }
    break;
                    case "decrypt":
                        if (algorithm.equals("RSA")) {
                            result = CryptoOperations.decryptRSA(inputText);
                        } else {
                            result = CryptoOperations.decryptSymmetric(algorithm, inputText, secretKey);
                        }
                        break;
                    case "encode":
                        result = CryptoOperations.encode(algorithm, inputText);
                        break;
                    case "decode":
                        result = CryptoOperations.decode(algorithm, inputText);
                        break;
                    case "hash":
                        result = CryptoOperations.hashText(algorithm, inputText, salt);
                        break;
                }
                
                // Send result back to HTML
                ctx.result(result);

            } catch (Exception e) {
                ctx.result("Error processing request: " + e.getMessage());
            }
        });
    }
}