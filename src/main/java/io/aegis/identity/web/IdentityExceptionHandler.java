package io.aegis.identity.web;

import io.aegis.identity.service.GroupService.DuplicateGroupException;
import io.aegis.identity.service.GroupService.GroupNotFoundException;
import io.aegis.identity.service.UserExceptions.DuplicateUserException;
import io.aegis.identity.service.UserExceptions.IncorrectPasswordException;
import io.aegis.identity.service.UserExceptions.PasswordPolicyException;
import io.aegis.identity.service.UserExceptions.SignupNotAvailableException;
import io.aegis.identity.service.UserExceptions.UserNotFoundException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/** Maps identity domain exceptions to RFC-7807 responses. The generic fallback lives in
 * {@code aegis-web-commons} ApiExceptionHandler. */
@RestControllerAdvice
public class IdentityExceptionHandler {

    @ExceptionHandler(io.aegis.identity.agent.AgentExceptions.AgentOwnerInvalidException.class)
    public ProblemDetail handleAgentOwnerInvalid(
            io.aegis.identity.agent.AgentExceptions.AgentOwnerInvalidException ex) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, ex.getMessage());
    }

    @ExceptionHandler(io.aegis.identity.agent.AgentExceptions.DuplicateAgentException.class)
    public ProblemDetail handleDuplicateAgent(
            io.aegis.identity.agent.AgentExceptions.DuplicateAgentException ex) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, ex.getMessage());
    }

    @ExceptionHandler(io.aegis.identity.agent.AgentExceptions.AgentNotFoundException.class)
    public ProblemDetail handleAgentNotFound(
            io.aegis.identity.agent.AgentExceptions.AgentNotFoundException ex) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, ex.getMessage());
    }

    @ExceptionHandler(io.aegis.identity.agent.AgentExceptions.AgentRevokedException.class)
    public ProblemDetail handleAgentRevoked(
            io.aegis.identity.agent.AgentExceptions.AgentRevokedException ex) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, ex.getMessage());
    }

    @ExceptionHandler(DuplicateUserException.class)
    public ProblemDetail handleDuplicate(DuplicateUserException ex) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, ex.getMessage());
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ProblemDetail handleNotFound(UserNotFoundException ex) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, ex.getMessage());
    }

    @ExceptionHandler(SignupNotAvailableException.class)
    public ProblemDetail handleSignupClosed(SignupNotAvailableException ex) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN, ex.getMessage());
    }

    @ExceptionHandler(PasswordPolicyException.class)
    public ProblemDetail handlePasswordPolicy(PasswordPolicyException ex) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, ex.getMessage());
    }

    @ExceptionHandler(IncorrectPasswordException.class)
    public ProblemDetail handleIncorrectPassword(IncorrectPasswordException ex) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, ex.getMessage());
    }

    @ExceptionHandler(DuplicateGroupException.class)
    public ProblemDetail handleDuplicateGroup(DuplicateGroupException ex) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, ex.getMessage());
    }

    @ExceptionHandler(GroupNotFoundException.class)
    public ProblemDetail handleGroupNotFound(GroupNotFoundException ex) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, ex.getMessage());
    }
}
