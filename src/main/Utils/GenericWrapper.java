package Utils;

import org.openqa.selenium.*;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.edge.EdgeDriver;
import org.openqa.selenium.edge.EdgeOptions;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.firefox.FirefoxOptions;
import org.openqa.selenium.interactions.Actions;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.testng.Assert;
import org.testng.asserts.SoftAssert;

import javax.imageio.ImageIO;
import java.awt.Rectangle;
import java.awt.Robot;
import java.awt.Toolkit;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

public class GenericWrapper {

    protected WebDriver driver;
    protected WebDriverWait wait;
    protected Actions actions;
    protected JavascriptExecutor jsExecutor;
    protected SoftAssert softAssert = new SoftAssert();

    protected AsyncEncryption asyncEncryption = new AsyncEncryption();
    protected String storedPublicKey;
    protected String storedPrivateKey;

    private ScheduledExecutorService screenRecorderScheduler;
    private final AtomicLong frameCounter = new AtomicLong(0);

    // =========================================================
    // Asymmetric Encryption Key Management
    // =========================================================
    protected Map<String, String> generateAndSaveKeys() {
        Map<String, String> keys = asyncEncryption.generateKeyPair();
        this.storedPublicKey = keys.get("publicKey");
        this.storedPrivateKey = keys.get("privateKey");
        return keys;
    }

    protected void generateAndSaveKeys(String targetDirectory) {
        Map<String, String> keys = generateAndSaveKeys();
        File dir = new File(targetDirectory);
        if (!dir.exists()) {
            dir.mkdirs();
        }
        try {
            File pubKeyFile = new File(dir, "public.key");
            File privKeyFile = new File(dir, "private.key");

            try (FileOutputStream fos = new FileOutputStream(pubKeyFile)) {
                fos.write(keys.get("publicKey").getBytes());
            }
            try (FileOutputStream fos = new FileOutputStream(privKeyFile)) {
                fos.write(keys.get("privateKey").getBytes());
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to save RSA keys to disk: " + e.getMessage(), e);
        }
    }

    private String processInputText(String text, boolean encrypted) {
        if (!encrypted) {
            return text;
        }
        return asyncEncryption.decrypt(text);
    }

    // =========================================================
    // 1) Invoke Browser (Headless on Linux, 1920x1080 Lock & Config URL)
    // =========================================================
    protected void invokeBrowser(String browserName, Duration explicitWaitDuration, Map<String, String> configMap) {
        String os = System.getProperty("os.name").toLowerCase();
        boolean isLinux = os.contains("linux");

        if (browserName.equalsIgnoreCase("chrome")) {
            ChromeOptions options = new ChromeOptions();
            options.addArguments("--remote-allow-origins=*");
            if (isLinux) {
                options.addArguments("--headless=new");
                options.addArguments("--no-sandbox");
                options.addArguments("--disable-dev-shm-usage");
                options.addArguments("--disable-gpu");
            }
            options.addArguments("--window-size=1920,1080");
            driver = new ChromeDriver(options);

        } else if (browserName.equalsIgnoreCase("firefox")) {
            FirefoxOptions options = new FirefoxOptions();
            if (isLinux) {
                options.addArguments("-headless");
            }
            options.addArguments("--width=1920");
            options.addArguments("--height=1080");
            driver = new FirefoxDriver(options);

        } else if (browserName.equalsIgnoreCase("edge")) {
            EdgeOptions options = new EdgeOptions();
            if (isLinux) {
                options.addArguments("--headless=new");
                options.addArguments("--no-sandbox");
                options.addArguments("--disable-dev-shm-usage");
            }
            options.addArguments("--window-size=1920,1080");
            driver = new EdgeDriver(options);

        } else {
            throw new IllegalArgumentException("Unsupported browser: " + browserName);
        }

        driver.manage().window().setSize(new Dimension(1920, 1080));
        driver.manage().timeouts().pageLoadTimeout(Duration.ofSeconds(60));

        this.wait = new WebDriverWait(driver, explicitWaitDuration);
        this.actions = new Actions(driver);
        this.jsExecutor = (JavascriptExecutor) driver;

        // Fetch URL from Config HashMap and navigate
        if (configMap != null) {
            String url = configMap.get("URL");
            if (url == null || url.trim().isEmpty()) {
                url = configMap.get("url");
            }
            if (url != null && !url.trim().isEmpty()) {
                driver.get(url.trim());
            } else {
                throw new IllegalArgumentException("Key 'URL' or 'url' not found or empty in provided configMap.");
            }
        }
    }

    // =========================================================
    // 2) Start taking screenshot 30 times/sec parallel
    // =========================================================
    protected void startParallelScreenCapture(String outputDirectory) {
        File dir = new File(outputDirectory);
        if (!dir.exists()) {
            dir.mkdirs();
        }

        screenRecorderScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "Parallel-Screen-Capture-Thread");
            t.setDaemon(true);
            return t;
        });

        screenRecorderScheduler.scheduleAtFixedRate(() -> {
            try {
                Robot robot = new Robot();
                Rectangle screenRect = new Rectangle(Toolkit.getDefaultToolkit().getScreenSize());
                BufferedImage screenCapture = robot.createScreenCapture(screenRect);

                long frameIndex = frameCounter.incrementAndGet();
                File target = new File(outputDirectory, String.format("frame_%08d.jpg", frameIndex));
                ImageIO.write(screenCapture, "jpg", target);
            } catch (Exception e) {
                // Drop frame silently to prevent loop stutter
            }
        }, 0, 33333, TimeUnit.MICROSECONDS);
    }

    protected void stopParallelScreenCapture() {
        if (screenRecorderScheduler != null && !screenRecorderScheduler.isShutdown()) {
            screenRecorderScheduler.shutdown();
            try {
                if (!screenRecorderScheduler.awaitTermination(2, TimeUnit.SECONDS)) {
                    screenRecorderScheduler.shutdownNow();
                }
            } catch (InterruptedException e) {
                screenRecorderScheduler.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
    }

    // =========================================================
    // 4) Explicit Waits
    // =========================================================
    protected WebElement waitForClickable(By locator) {
        try {
            return wait.until(ExpectedConditions.elementToBeClickable(locator));
        } catch (TimeoutException e) {
            throw new RuntimeException("Element not clickable within timeout for locator: " + locator, e);
        }
    }

    protected WebElement waitForVisible(By locator) {
        try {
            return wait.until(ExpectedConditions.visibilityOfElementLocated(locator));
        } catch (TimeoutException e) {
            throw new RuntimeException("Element not visible within timeout for locator: " + locator, e);
        }
    }

    protected WebElement waitForTypeable(By locator) {
        try {
            return wait.until(d -> {
                WebElement element = d.findElement(locator);
                return (element.isDisplayed() && element.isEnabled()) ? element : null;
            });
        } catch (TimeoutException e) {
            throw new RuntimeException("Element not typeable within timeout for locator: " + locator, e);
        }
    }

    protected WebElement waitForClickableNth(By locator, int index) {
        try {
            return wait.until(d -> {
                List<WebElement> elements = d.findElements(locator);
                if (elements.size() > index) {
                    WebElement el = elements.get(index);
                    return (el.isDisplayed() && el.isEnabled()) ? el : null;
                }
                return null;
            });
        } catch (TimeoutException e) {
            throw new RuntimeException("Element at index [" + index + "] not clickable for locator: " + locator, e);
        }
    }

    protected WebElement waitForVisibleNth(By locator, int index) {
        try {
            return wait.until(d -> {
                List<WebElement> elements = d.findElements(locator);
                if (elements.size() > index && elements.get(index).isDisplayed()) {
                    return elements.get(index);
                }
                return null;
            });
        } catch (TimeoutException e) {
            throw new RuntimeException("Element at index [" + index + "] not visible for locator: " + locator, e);
        }
    }

    protected WebElement waitForTypeableNth(By locator, int index) {
        return waitForClickableNth(locator, index);
    }

    // =========================================================
    // 5) Click Functions
    // =========================================================
    protected void clickSelenium(By locator) {
        try {
            waitForClickable(locator).click();
        } catch (Exception e) {
            throw new RuntimeException("Failed to perform Selenium Click on locator: " + locator + ". Reason: " + e.getMessage(), e);
        }
    }

    protected void clickAction(By locator) {
        try {
            WebElement element = waitForClickable(locator);
            actions.moveToElement(element).click().perform();
        } catch (Exception e) {
            throw new RuntimeException("Failed to perform Actions Click on locator: " + locator + ". Reason: " + e.getMessage(), e);
        }
    }

    protected void clickJavascript(By locator) {
        try {
            WebElement element = waitForVisible(locator);
            jsExecutor.executeScript("arguments[0].click();", element);
        } catch (Exception e) {
            throw new RuntimeException("Failed to perform JavaScript Click on locator: " + locator + ". Reason: " + e.getMessage(), e);
        }
    }

    // =========================================================
    // 6) TypeElement with `encrypted` Flag Support
    // =========================================================
    protected void typeElementSendKeys(By locator, String text, boolean encrypted) {
        try {
            String valueToType = processInputText(text, encrypted);
            WebElement element = waitForTypeable(locator);
            element.clear();
            element.sendKeys(valueToType);
        } catch (Exception e) {
            throw new RuntimeException("Failed to send keys to locator: " + locator + ". Reason: " + e.getMessage(), e);
        }
    }

    protected void typeElementAction(By locator, String text, boolean encrypted) {
        try {
            String valueToType = processInputText(text, encrypted);
            WebElement element = waitForTypeable(locator);
            actions.moveToElement(element).click().sendKeys(valueToType).perform();
        } catch (Exception e) {
            throw new RuntimeException("Failed to perform Actions Type on locator: " + locator + ". Reason: " + e.getMessage(), e);
        }
    }

    protected void typeElementJSE(By locator, String text, boolean encrypted) {
        try {
            String valueToType = processInputText(text, encrypted);
            WebElement element = waitForVisible(locator);
            jsExecutor.executeScript("arguments[0].value = arguments[1]; arguments[0].dispatchEvent(new Event('input'));", element, valueToType);
        } catch (Exception e) {
            throw new RuntimeException("Failed to perform JavaScript Type on locator: " + locator + ". Reason: " + e.getMessage(), e);
        }
    }

    // =========================================================
    // 7) TypeKey
    // =========================================================
    protected void typeKeySendKeys(By locator, Keys key) {
        try {
            WebElement element = waitForTypeable(locator);
            element.sendKeys(key);
        } catch (Exception e) {
            throw new RuntimeException("Failed to send Key [" + key.name() + "] to locator: " + locator + ". Reason: " + e.getMessage(), e);
        }
    }

    protected void typeKeyAction(By locator, Keys key) {
        try {
            WebElement element = waitForTypeable(locator);
            actions.moveToElement(element).click().sendKeys(key).perform();
        } catch (Exception e) {
            throw new RuntimeException("Failed to perform Actions Key [" + key.name() + "] on locator: " + locator + ". Reason: " + e.getMessage(), e);
        }
    }

    protected void typeKeyJSE(By locator, Keys key) {
        try {
            WebElement element = waitForVisible(locator);
            String eventJs = "arguments[0].dispatchEvent(new KeyboardEvent('keydown', {'key': '" + key.name() + "'}));";
            jsExecutor.executeScript(eventJs, element);
        } catch (Exception e) {
            throw new RuntimeException("Failed to perform JavaScript Key [" + key.name() + "] on locator: " + locator + ". Reason: " + e.getMessage(), e);
        }
    }

    // =========================================================
    // 8) Nth Element Operations with `encrypted` Flag Support
    // =========================================================
    protected void clickSeleniumNth(By locator, int index) {
        try {
            waitForClickableNth(locator, index).click();
        } catch (Exception e) {
            throw new RuntimeException("Failed to perform Selenium Click on locator: " + locator + " at index: " + index + ". Reason: " + e.getMessage(), e);
        }
    }

    protected void clickActionNth(By locator, int index) {
        try {
            WebElement element = waitForClickableNth(locator, index);
            actions.moveToElement(element).click().perform();
        } catch (Exception e) {
            throw new RuntimeException("Failed to perform Actions Click on locator: " + locator + " at index: " + index + ". Reason: " + e.getMessage(), e);
        }
    }

    protected void clickJavascriptNth(By locator, int index) {
        try {
            WebElement element = waitForVisibleNth(locator, index);
            jsExecutor.executeScript("arguments[0].click();", element);
        } catch (Exception e) {
            throw new RuntimeException("Failed to perform JavaScript Click on locator: " + locator + " at index: " + index + ". Reason: " + e.getMessage(), e);
        }
    }

    protected void typeElementSendKeysNth(By locator, int index, String text, boolean encrypted) {
        try {
            String valueToType = processInputText(text, encrypted);
            WebElement element = waitForTypeableNth(locator, index);
            element.clear();
            element.sendKeys(valueToType);
        } catch (Exception e) {
            throw new RuntimeException("Failed to send keys to locator: " + locator + " at index: " + index + ". Reason: " + e.getMessage(), e);
        }
    }

    protected void typeElementActionNth(By locator, int index, String text, boolean encrypted) {
        try {
            String valueToType = processInputText(text, encrypted);
            WebElement element = waitForTypeableNth(locator, index);
            actions.moveToElement(element).click().sendKeys(valueToType).perform();
        } catch (Exception e) {
            throw new RuntimeException("Failed to perform Actions Type on locator: " + locator + " at index: " + index + ". Reason: " + e.getMessage(), e);
        }
    }

    protected void typeElementJSENth(By locator, int index, String text, boolean encrypted) {
        try {
            String valueToType = processInputText(text, encrypted);
            WebElement element = waitForVisibleNth(locator, index);
            jsExecutor.executeScript("arguments[0].value = arguments[1]; arguments[0].dispatchEvent(new Event('input'));", element, valueToType);
        } catch (Exception e) {
            throw new RuntimeException("Failed to perform JavaScript Type on locator: " + locator + " at index: " + index + ". Reason: " + e.getMessage(), e);
        }
    }

    protected void typeKeySendKeysNth(By locator, int index, Keys key) {
        try {
            WebElement element = waitForTypeableNth(locator, index);
            element.sendKeys(key);
        } catch (Exception e) {
            throw new RuntimeException("Failed to send Key [" + key.name() + "] to locator: " + locator + " at index: " + index + ". Reason: " + e.getMessage(), e);
        }
    }

    protected void typeKeyActionNth(By locator, int index, Keys key) {
        try {
            WebElement element = waitForTypeableNth(locator, index);
            actions.moveToElement(element).click().sendKeys(key).perform();
        } catch (Exception e) {
            throw new RuntimeException("Failed to perform Actions Key [" + key.name() + "] on locator: " + locator + " at index: " + index + ". Reason: " + e.getMessage(), e);
        }
    }

    protected void typeKeyJSENth(By locator, int index, Keys key) {
        try {
            WebElement element = waitForVisibleNth(locator, index);
            String eventJs = "arguments[0].dispatchEvent(new KeyboardEvent('keydown', {'key': '" + key.name() + "'}));";
            jsExecutor.executeScript(eventJs, element);
        } catch (Exception e) {
            throw new RuntimeException("Failed to perform JavaScript Key [" + key.name() + "] on locator: " + locator + " at index: " + index + ". Reason: " + e.getMessage(), e);
        }
    }

    // =========================================================
    // 9 & 10) Frame Switching
    // =========================================================
    protected void switchToFrame(int frameIndex) {
        try {
            wait.until(ExpectedConditions.frameToBeAvailableAndSwitchToIt(frameIndex));
        } catch (Exception e) {
            throw new RuntimeException("Failed to switch to frame at index: " + frameIndex, e);
        }
    }

    protected void switchToFrame(String nameOrId) {
        try {
            wait.until(ExpectedConditions.frameToBeAvailableAndSwitchToIt(nameOrId));
        } catch (Exception e) {
            throw new RuntimeException("Failed to switch to frame with name or ID: " + nameOrId, e);
        }
    }

    protected void switchToFrame(By locator) {
        try {
            wait.until(ExpectedConditions.frameToBeAvailableAndSwitchToIt(locator));
        } catch (Exception e) {
            throw new RuntimeException("Failed to switch to frame located by: " + locator, e);
        }
    }

    protected void switchToMainFrame() {
        try {
            driver.switchTo().defaultContent();
        } catch (Exception e) {
            throw new RuntimeException("Failed to switch to main default frame content", e);
        }
    }

    // =========================================================
    // 11) Hard Assert
    // =========================================================
    protected void hardAssertTrue(boolean condition, String message) {
        Assert.assertTrue(condition, message);
    }

    protected void hardAssertEquals(Object actual, Object expected, String message) {
        Assert.assertEquals(actual, expected, message);
    }

    // =========================================================
    // 12) Soft Assert
    // =========================================================
    protected void softAssertTrue(boolean condition, String message) {
        softAssert.assertTrue(condition, message);
    }

    protected void softAssertEquals(Object actual, Object expected, String message) {
        softAssert.assertEquals(actual, expected, message);
    }

    protected void assertAll() {
        softAssert.assertAll();
    }

    // =========================================================
    // 13) Calls function in ExcelReader to get Key Value in HashMap
    // =========================================================
    protected Map<String, String> getExcelData(String filePath, String sheetName) {
        return ExcelReader.getDataAsMap(filePath, sheetName);
    }

    // =========================================================
    // 14) Loads Key Value pair from Properties file for xpaths
    // =========================================================
    protected Map<String, By> loadLocatorsFromProperties(String propertiesFilePath) {
        Map<String, By> locatorMap = new HashMap<>();
        Properties properties = new Properties();

        try (InputStream input = new FileInputStream(propertiesFilePath)) {
            properties.load(input);
            for (String key : properties.stringPropertyNames()) {
                String xpathValue = properties.getProperty(key);
                locatorMap.put(key, By.xpath(xpathValue));
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to read properties file at: " + propertiesFilePath, e);
        }
        return locatorMap;
    }

    // =========================================================
    // Teardown / Cleanup
    // =========================================================
    protected void quitBrowser() {
        stopParallelScreenCapture();
        if (driver != null) {
            driver.quit();
        }
    }
}