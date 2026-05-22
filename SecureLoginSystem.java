import java.security.MessageDigest;
import java.util.*;

public class SecureLoginSystem {

    static HashMap<String, String> users = new HashMap<>();
    static boolean loggedIn = false;
    static String currentUser = "";

    // SHA-256 Password Hashing
    public static String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(password.getBytes());

            StringBuilder sb = new StringBuilder();

            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }

            return sb.toString();

        } catch (Exception e) {
            return null;
        }
    }

    // Input Validation + SQL Injection Check
    public static boolean isValid(String input) {

        String[] blocked = {
                "'", "\"", ";", "--",
                "drop", "delete",
                "insert", "update",
                "select", "or 1=1"
        };

        String lower = input.toLowerCase();

        for (String s : blocked) {
            if (lower.contains(s)) {
                return false;
            }
        }

        return true;
    }

    public static void main(String[] args) {

        Scanner sc = new Scanner(System.in);

        while (true) {

            System.out.println("\n===== SECURE LOGIN SYSTEM =====");
            System.out.println("1. Register");
            System.out.println("2. Login");
            System.out.println("3. Logout");
            System.out.println("4. Exit");
            System.out.print("Enter Choice: ");

            int choice = sc.nextInt();
            sc.nextLine();

            switch (choice) {

                case 1:

                    System.out.print("Enter Username: ");
                    String user = sc.nextLine();

                    System.out.print("Enter Password: ");
                    String pass = sc.nextLine();

                    if (!isValid(user) || !isValid(pass)) {

                        System.out.println(
                                "Invalid Input / SQL Injection Detected!"
                        );

                        break;
                    }

                    users.put(user, hashPassword(pass));

                    System.out.println(
                            "Registration Successful!"
                    );

                    break;

                case 2:

                    System.out.print("Enter Username: ");
                    String loginUser = sc.nextLine();

                    System.out.print("Enter Password: ");
                    String loginPass = sc.nextLine();

                    if (!users.containsKey(loginUser)) {

                        System.out.println("User Not Found");
                        break;
                    }

                    String storedHash =
                            users.get(loginUser);

                    if (!storedHash.equals(
                            hashPassword(loginPass))) {

                        System.out.println(
                                "Wrong Password"
                        );

                        break;
                    }

                    // 2FA OTP
                    Random random = new Random();

                    int otp =
                            1000 + random.nextInt(9000);

                    System.out.println(
                            "Generated OTP: " + otp
                    );

                    System.out.print(
                            "Enter OTP: "
                    );

                    int enteredOtp =
                            Integer.parseInt(
                                    sc.nextLine()
                            );

                    if (enteredOtp != otp) {

                        System.out.println(
                                "Invalid OTP"
                        );

                        break;
                    }

                    loggedIn = true;

                    currentUser = loginUser;

                    System.out.println(
                            "\nLogin Successful!"
                    );

                    System.out.println(
                            "Session Started for "
                                    + currentUser
                    );

                    break;

                case 3:

                    if (loggedIn) {

                        loggedIn = false;

                        currentUser = "";

                        System.out.println(
                                "Logout Successful!"
                        );

                    } else {

                        System.out.println(
                                "No Active Session"
                        );
                    }

                    break;

                case 4:

                    System.out.println(
                            "Program Closed"
                    );

                    sc.close();

                    System.exit(0);

                default:

                    System.out.println(
                            "Invalid Choice"
                    );
            }
        }
    }
}