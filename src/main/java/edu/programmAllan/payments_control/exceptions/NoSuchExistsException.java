package edu.programmAllan.payments_control.exceptions;

public class NoSuchExistsException extends RuntimeException {
    private String message;

    public NoSuchExistsException() {}

    public NoSuchExistsException(String msg) {
        super(msg);
        this.message = msg;
    }
}
