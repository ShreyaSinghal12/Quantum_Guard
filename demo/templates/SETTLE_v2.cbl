       IDENTIFICATION DIVISION.
       PROGRAM-ID. SETTLE.
      * SYNTHETIC demo program - not production code.
      * The old design generated keys here:
      *    CALL 'CSNDPKG' USING WS-RETURN-CODE WS-REASON-CODE.
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01  WS-KEY-TYPE          PIC X(8)  VALUE 'ECC-PAIR'.
       01  WS-RETURN-CODE       PIC S9(8) COMP.
       01  WS-REASON-CODE       PIC S9(8) COMP.
       PROCEDURE DIVISION.
      * Derive the settlement session key with the clearing house.
           CALL 'CSNDEDH' USING WS-RETURN-CODE WS-REASON-CODE.
      * Send the session key to the partner bank, wrapped under its public key.
           CALL 'CSNDSYX' USING WS-RETURN-CODE WS-REASON-CODE. *> partner export
           GOBACK.
