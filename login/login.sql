DELIMITER //

DROP PROCEDURE IF EXISTS sp_LoginUser //

CREATE PROCEDURE sp_LoginUser(
    IN p_email VARCHAR(150)
)
BEGIN
    SELECT 
        id,
        firstname,
        lastname,
        email,
        password,
        roletype
    FROM users 
    WHERE email = p_email 
    LIMIT 1;
END //

DELIMITER ;
