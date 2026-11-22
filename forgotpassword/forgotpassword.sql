DELIMITER //

DROP PROCEDURE IF EXISTS sp_ResetPassword //

CREATE PROCEDURE sp_ResetPassword(
    IN p_email VARCHAR(150),
    IN p_new_password VARCHAR(255)
)
BEGIN
    IF NOT EXISTS (SELECT 1 FROM users WHERE email = p_email) THEN
        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'User not found';
    ELSE
        UPDATE users 
        SET password = p_new_password 
        WHERE email = p_email;
    END IF;
END //

DROP PROCEDURE IF EXISTS sp_GetUserTOTPSecret //

CREATE PROCEDURE sp_GetUserTOTPSecret(
    IN p_email VARCHAR(150)
)
BEGIN
    SELECT totp_secret 
    FROM users 
    WHERE email = p_email 
    LIMIT 1;
END //

DELIMITER ;
