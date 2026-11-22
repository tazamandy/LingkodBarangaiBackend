DELIMITER //

DROP PROCEDURE IF EXISTS sp_HealthCheck //

CREATE PROCEDURE sp_HealthCheck()
BEGIN
    SELECT 
        'healthy' AS db_status, 
        NOW() AS server_time;
END //

DELIMITER ;
