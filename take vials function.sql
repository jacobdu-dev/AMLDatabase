DELIMITER $$
CREATE FUNCTION TAKE_VIAL (ptID INT, uID INT, noVials INT, sampleType INT, sampleID INT, experiment VARCHAR(255)) 
RETURNS INT 
NOT DETERMINISTIC
BEGIN
    DECLARE num INT;
    IF (sampleType = 0) THEN
        SELECT COUNT(*) INTO num FROM pbCollection WHERE pbID = sampleID AND vials >= noVials;
    END IF;
    IF (sampleType = 1) THEN
        SELECT COUNT(*) INTO num FROM bmCollection WHERE bmID = sampleID AND vials >= noVials;
    END IF;

    IF (sampleType = 0) AND (num > 0) THEN
        UPDATE pbCollection SET vials = vials - noVials WHERE pbID = sampleID;
    END IF;

    IF (sampleType = 1) AND (num > 0) THEN
        UPDATE bmCollection SET vials = vials - noVials WHERE bmID = sampleID;
    END IF;

    IF (num > 0) THEN
        INSERT INTO vialLog (ptID, vialsTaken, sampleType, sampleID, uID, expr)  VALUES (ptID, noVials, sampleType, sampleID, uID, experiment);
        RETURN 0;
    END IF;
    RETURN 1;
    END$$
DELIMITER ;



