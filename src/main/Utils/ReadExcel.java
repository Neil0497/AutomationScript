package Utils;

import org.apache.poi.ss.usermodel.*;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ExcelReader {

    private static final DataFormatter FORMATTER = new DataFormatter();
    
    // Headers to be encrypted (case-insensitive check)
    private static final List<String> ENCRYPTED_HEADERS = Arrays.asList("username", "password", "login");

    // Backward-compatible delegator matching GenericWrapper step 13
    public static Map<String, String> getDataAsMap(String filePath, String sheetName) {
        return readConfigFile(filePath, sheetName);
    }

    /**
     * 1) Reads a config sheet where one column has header "Key" and another has header "Value".
     * Maps each row's Key column content to its Value column content.
     */
    public static Map<String, String> readConfigFile(String filePath, String sheetName) {
        Map<String, String> configMap = new HashMap<>();

        try (FileInputStream fis = new FileInputStream(filePath);
             Workbook workbook = WorkbookFactory.create(fis)) {

            Sheet sheet = workbook.getSheet(sheetName);
            if (sheet == null) {
                throw new IllegalArgumentException("Sheet '" + sheetName + "' not found in workbook: " + filePath);
            }

            Row headerRow = sheet.getRow(0);
            if (headerRow == null) {
                throw new IllegalStateException("Header row (row 0) is missing in sheet: " + sheetName);
            }

            int keyColIndex = -1;
            int valueColIndex = -1;

            for (Cell cell : headerRow) {
                String headerText = FORMATTER.formatCellValue(cell).trim();
                if (headerText.equalsIgnoreCase("Key")) {
                    keyColIndex = cell.getColumnIndex();
                } else if (headerText.equalsIgnoreCase("Value")) {
                    valueColIndex = cell.getColumnIndex();
                }
            }

            if (keyColIndex == -1 || valueColIndex == -1) {
                throw new IllegalStateException(
                    "Config sheet must contain columns with headers 'Key' and 'Value'. Found headers in sheet: " + sheetName
                );
            }

            for (int r = 1; r <= sheet.getLastRowNum(); r++) {
                Row row = sheet.getRow(r);
                if (row == null) {
                    continue;
                }

                Cell keyCell = row.getCell(keyColIndex);
                Cell valCell = row.getCell(valueColIndex);

                String key = (keyCell != null) ? FORMATTER.formatCellValue(keyCell).trim() : "";
                String value = (valCell != null) ? FORMATTER.formatCellValue(valCell).trim() : "";

                if (!key.isEmpty()) {
                    configMap.put(key, value);
                }
            }

        } catch (IOException e) {
            throw new RuntimeException("Error reading Excel config file at '" + filePath + "': " + e.getMessage(), e);
        }

        return configMap;
    }

    /**
     * 2) Reads test data from a specific row number.
     * Encrypts the value using the provided Base64 Public Key if the column header is
     * "Username", "Password", or "Login" (case-insensitive).
     *
     * @param filePath        Workbook path
     * @param sheetName       Sheet name
     * @param rowIndex        Target row index (>= 1)
     * @param base64PublicKey Public Key string used to encrypt sensitive values
     * @return Map of Header -> (possibly encrypted) Cell Value
     */
    public static Map<String, String> readTestDataByRow(String filePath, String sheetName, int rowIndex, String base64PublicKey) {
        AsyncEncryption encryption = new AsyncEncryption();
        encryption.setPublicKey(base64PublicKey);

        return readTestDataInternal(filePath, sheetName, rowIndex, encryption);
    }

    /**
     * Overload: Accepts a PublicKey object directly.
     */
    public static Map<String, String> readTestDataByRow(String filePath, String sheetName, int rowIndex, PublicKey publicKey) {
        AsyncEncryption encryption = new AsyncEncryption();
        // Sets the internal public key directly if you add setPublicKey(PublicKey) or convert to base64
        encryption.setPublicKey(java.util.Base64.getEncoder().encodeToString(publicKey.getEncoded()));

        return readTestDataInternal(filePath, sheetName, rowIndex, encryption);
    }

    private static Map<String, String> readTestDataInternal(String filePath, String sheetName, int rowIndex, AsyncEncryption encryption) {
        Map<String, String> testDataMap = new HashMap<>();

        if (rowIndex <= 0) {
            throw new IllegalArgumentException("Target data rowIndex must be >= 1 (row 0 is reserved for headers). Received: " + rowIndex);
        }

        try (FileInputStream fis = new FileInputStream(filePath);
             Workbook workbook = WorkbookFactory.create(fis)) {

            Sheet sheet = workbook.getSheet(sheetName);
            if (sheet == null) {
                throw new IllegalArgumentException("Sheet '" + sheetName + "' not found in workbook: " + filePath);
            }

            Row headerRow = sheet.getRow(0);
            if (headerRow == null) {
                throw new IllegalStateException("Header row (row 0) is missing in sheet: " + sheetName);
            }

            Row dataRow = sheet.getRow(rowIndex);
            if (dataRow == null) {
                throw new IllegalArgumentException("Row index " + rowIndex + " does not exist or is empty in sheet: " + sheetName);
            }

            int lastCellNum = headerRow.getLastCellNum();

            for (int colIndex = 0; colIndex < lastCellNum; colIndex++) {
                Cell headerCell = headerRow.getCell(colIndex);
                String headerName = (headerCell != null) ? FORMATTER.formatCellValue(headerCell).trim() : "";

                if (headerName.isEmpty()) {
                    continue;
                }

                Cell dataCell = dataRow.getCell(colIndex);
                String cellValue = (dataCell != null) ? FORMATTER.formatCellValue(dataCell).trim() : "";

                // Case-insensitive check: "Username", "Password", or "Login"
                if (isSensitiveHeader(headerName) && !cellValue.isEmpty()) {
                    cellValue = encryption.encrypt(cellValue);
                }

                testDataMap.put(headerName, cellValue);
            }

        } catch (IOException e) {
            throw new RuntimeException("Error reading Excel test data from '" + filePath + "': " + e.getMessage(), e);
        }

        return testDataMap;
    }

    private static boolean isSensitiveHeader(String headerName) {
        return ENCRYPTED_HEADERS.stream().anyMatch(h -> h.equalsIgnoreCase(headerName.trim()));
    }
}