CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    firstname VARCHAR(100) NOT NULL,
    middlename VARCHAR(100),
    lastname VARCHAR(100) NOT NULL,
    suffix VARCHAR(20),
    gender_id INT NOT NULL,
    religion VARCHAR(100),
    nationality VARCHAR(100) DEFAULT 'Filipino',
    roletype VARCHAR(50) NOT NULL,
    housenumber VARCHAR(50),
    purok VARCHAR(100),
    barangay VARCHAR(100) NOT NULL,
    municipality VARCHAR(100) NOT NULL,
    province VARCHAR(100) NOT NULL,
    zipcode VARCHAR(20),
    email VARCHAR(150) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    totp_secret VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

DELIMITER //

DROP PROCEDURE IF EXISTS sp_RegisterUser //

CREATE PROCEDURE sp_RegisterUser(
    IN p_firstname VARCHAR(100),
    IN p_middlename VARCHAR(100),
    IN p_lastname VARCHAR(100),
    IN p_suffix VARCHAR(20),
    IN p_gender_id INT,
    IN p_religion VARCHAR(100),
    IN p_nationality VARCHAR(100),
    IN p_roletype VARCHAR(50),
    IN p_housenumber VARCHAR(50),
    IN p_purok VARCHAR(100),
    IN p_barangay VARCHAR(100),
    IN p_municipality VARCHAR(100),
    IN p_province VARCHAR(100),
    IN p_zipcode VARCHAR(20),
    IN p_email VARCHAR(150),
    IN p_password VARCHAR(255),
    IN p_totp_secret VARCHAR(100)
)
BEGIN
    IF EXISTS (SELECT 1 FROM users WHERE email = p_email) THEN
        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Email already exists';
    ELSE
        INSERT INTO users (
            firstname,
            middlename,
            lastname,
            suffix,
            gender_id,
            religion,
            nationality,
            roletype,
            housenumber,
            purok,
            barangay,
            municipality,
            province,
            zipcode,
            email,
            password,
            totp_secret
        ) VALUES (
            p_firstname,
            p_middlename,
            p_lastname,
            p_suffix,
            p_gender_id,
            p_religion,
            p_nationality,
            p_roletype,
            p_housenumber,
            p_purok,
            p_barangay,
            p_municipality,
            p_province,
            p_zipcode,
            p_email,
            p_password,
            p_totp_secret
        );
    END IF;
END //

DELIMITER ;
