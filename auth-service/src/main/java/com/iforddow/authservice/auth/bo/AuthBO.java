package com.iforddow.authservice.auth.bo;

import com.iforddow.authservice.auth.request.RegisterRequest;

import java.util.ArrayList;

public class AuthBO {

    /**
     * A method to validate the users registration
     *
     * @author IFD
     * @since 2025-07-22
     * */
    public ArrayList<String> validateUserRegistration(RegisterRequest registerRequest) {

        ArrayList<String> errors = new ArrayList<>();

        String email = registerRequest.getEmail();
        String password = registerRequest.getPassword();
        String confirmPassword = registerRequest.getConfirmPassword();

        // Simple regex for basic email validation
        String emailRegex = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$";

        if (email == null) {
            errors.add("Email is required");
        }   else {
            if(!email.matches(emailRegex)) {
                errors.add("Email format is not valid");
            }
        }

        if (password == null) {
            errors.add("Password is required");
        } else {
            if (!password.equals(confirmPassword)) {
                errors.add("Passwords do not match");
            }

            ArrayList<String> passwordValidationErrors = validatePassword(password);

            if(passwordValidationErrors != null) {
                errors.addAll(passwordValidationErrors);
            }
        }

        if (confirmPassword == null) {
            errors.add("Confirm password is required");
        }

        return errors;

    }

    /**
     * Validates the given password against the defined criteria.
     *
     * @param password the password to validate
     *
     * @return null if the password is valid, otherwise a validation error message
     *
     * @author IFD
     * @since  2025-06-14
     */
    public ArrayList<String> validatePassword(String password) {

        ArrayList<String> errors = new ArrayList<>();

        int MIN_LENGTH = 8;
        int MAX_LENGTH = 32;

        String oneUpperCaseRegex = ".*[A-Z].*";
        String oneLowerCaseRegex = ".*[a-z].*";
        String oneDigitRegex = ".*\\d.*";
        String specialCharRegex = ".*[!@#$%^&*(),.?\":{}|<>].*";

        if (password == null || password.isEmpty()) {
            errors.add("Password cannot be null or empty");
            return errors;
        }   else {
            if (password.length() < MIN_LENGTH || password.length() > MAX_LENGTH) {
                errors.add("Password must be between " + MIN_LENGTH + " and " + MAX_LENGTH + " characters long");
            }
            if (!password.matches(oneUpperCaseRegex)) {
                errors.add("Password must contain at least one uppercase letter");
            }
            if (!password.matches(oneLowerCaseRegex)) {
                errors.add("Password must contain at least one lowercase letter");
            }
            if (!password.matches(oneDigitRegex)) {
                errors.add("Password must contain at least one digit");
            }
            if (!password.matches(specialCharRegex)) {
                errors.add("Password must contain at least one special character");
            }
        }

        return errors;
    }

    /*
     * A method to validate both a password and a confirmation
     * password. Note the confirmation password is a simple
     * equals check.
     *
     * @author IFD
     * @since 2025-07-24
     * */
    public ArrayList<String> validatePassword(String password, String confirmPassword) {

        ArrayList<String> errors = new ArrayList<>(validatePassword(password));

        if(!password.equals(confirmPassword)) {
            errors.add("Passwords do not match");
        }

        return errors;
    }

    /**
     * A method to validate changing a users password, will confirm
     * the new password meets requirements, and the new password
     * is not the same as the old.
     *
     * @author IFD
     * @since 2025-07-22
     * */
    public ArrayList<String> validatePassword(String oldPassword, String password, String confirmPassword) {

        ArrayList<String> errors = new ArrayList<>(validatePassword(password, confirmPassword));

        if(password.equals(oldPassword)) {
            errors.add("New password cannot be the same as the old password");
        }

        return errors;
    }

}
