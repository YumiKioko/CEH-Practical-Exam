here are four sub-tabs within Intruder:

  - **Positions**: This tab allows us to select an attack type (which we will cover in a future task) and configure where we want to insert our payloads in the request template.
  
- **Payloads**: Here we can select values to insert into the positions defined in the **Positions** tab. We have various payload options, such as loading items from a wordlist. The way these payloads are inserted into the template depends on the attack type chosen in the **Positions** tab. The **Payloads** tab also enables us to modify Intruder's behavior regarding payloads, such as defining pre-processing rules for each payload (e.g., adding a prefix or suffix, performing match and replace, or skipping payloads based on a defined regex).

- **Resource Pool**: This tab is not particularly useful in the Burp Community Edition. It allows for resource allocation among various automated tasks in Burp Professional. Without access to these automated tasks, this tab is of limited importance.

- **Settings**: This tab allows us to configure attack behavior. It primarily deals with how Burp handles results and the attack itself. For instance, we can flag requests containing specific text or define Burp's response to redirect (3xx) responses.

___

In the **Payloads** tab of Burp Suite Intruder, we can create, assign, and configure payloads for our attack. This sub-tab is divided into four sections:

- **Payload Sets**:

- This section allows us to choose the position for which we want to configure a payload set and select the type of payload we want to use.

- When using attack types that allow only a single payload set (Sniper or Battering Ram), the "Payload Set" dropdown will have only one option, regardless of the number of defined positions.

- If we use attack types that require multiple payload sets (Pitchfork or Cluster Bomb), there will be one item in the dropdown for each position.

- **Note:** When assigning numbers in the "Payload Set" dropdown for multiple positions, follow a top-to-bottom, left-to-right order. For example, with two positions (`username=§pentester§&password=§Expl01ted§`), the first item in the payload set dropdown would refer to the username field, and the second item would refer to the password field.

- **Payload settings**:

- This section provides options specific to the selected payload type for the current payload set.

- For example, when using the "Simple list" payload type, we can manually add or remove payloads to/from the set using the **Add** text box, **Paste** lines, or **Load** payloads from a file. The **Remove** button removes the currently selected line, and the **Clear** button clears the entire list. Be cautious with loading huge lists, as it may cause Burp to crash.

- Each payload type will have its own set of options and functionality. Explore the options available to understand the range of possibilities.

  - **Payload Processing**:

- In this section, we can define rules to be applied to each payload in the set before it is sent to the target.

- For example, we can capitalize every word, skip payloads that match a regex pattern, or apply other transformations or filtering.

- While you may not use this section frequently, it can be highly valuable when specific payload processing is required for your attack.

- **Payload Encoding**:

- The section allows us to customize the encoding options for our payloads.

- By default, Burp Suite applies URL encoding to ensure the safe transmission of payloads. However, there may be cases where we want to adjust the encoding behavior.

- We can override the default URL encoding options by modifying the list of characters to be encoded or unchecking the "URL-encode these characters" checkbox.


**Payload processing** rule could we use to add characters at the end of each payload in the set.

- `Add Suffix`

___

The **Positions** tab of Burp Suite Intruder has a dropdown menu for selecting the attack type. Intruder offers four attack types, each serving a specific purpose. Let's explore each of them:

1. **Sniper**: The Sniper attack type is the default and most commonly used option. It cycles through the payloads, inserting one payload at a time into each position defined in the request. Sniper attacks iterate through all the payloads in a linear fashion, allowing for precise and focused testing.

2. **Battering ram**: The Battering ram attack type differs from Sniper in that it sends all payloads simultaneously, each payload inserted into its respective position. This attack type is useful when testing for race conditions or when payloads need to be sent concurrently.

3. **Pitchfork**: The Pitchfork attack type enables the simultaneous testing of multiple positions with different payloads. It allows the tester to define multiple payload sets, each associated with a specific position in the request. Pitchfork attacks are effective when there are distinct parameters that need separate testing.

4. **Cluster bomb**: The Cluster bomb attack type combines the Sniper and Pitchfork approaches. It performs a Sniper-like attack on each position but simultaneously tests all payloads from each set. This attack type is useful when multiple positions have different payloads, and we want to test them all together.

  Each attack type has its advantages and is suitable for different testing scenarios. Understanding their differences helps us select the appropriate attack type based on the testing objectives.

  5. The **Sniper** attack type is the default and most commonly used attack type in Burp Suite Intruder.


It is particularly effective for single-position attacks, such as password brute-force or fuzzing for API endpoints. In a Sniper attack, we provide a set of payloads, which can be a wordlist or a range of numbers, and Intruder inserts each payload into each defined position in the request.

  
- The **Battering ram** attack type in Burp Suite Intruder differs from Sniper in that it places the same payload in every position simultaneously, rather than substituting each payload into each position in turn.
  

Using the Battering Ram attack type with the same wordlist from before (`burp`, `suite`, and `intruder`), Intruder would generate three requests:

  
|Request Number|Request Body|

|---|---|

|1|`username=burp&password=burp`|

|2|`username=suite&password=suite`|

|3|`username=intruder&password=intruder`|

  
As shown in the table, each payload from the wordlist is inserted into every position for each request made. In a Battering Ram attack, the same payload is thrown at every defined position simultaneously, providing a brute-force-like approach to testing.
 

## Burp Suite Macro #burp_macro Process for Extracting CSRF Token and Session Cookie

### Purpose:
  
Automate the extraction of dynamic **CSRF tokens** and **session cookies** before each brute-force request in Burp Suite Intruder. This is essential when dealing with login forms protected by anti-automation defenses like CSRF tokens and rotating session cookies.

---

### 1. Identifying the Token and Cookie
#### HTML Snippet (Example):


```html

<input type="hidden" name="loginToken" value="0641f49bb7a3cb35d3d7012190627c5c">

```
  
- **Location**: This hidden input field resides **inside the login form**, directly after the username and password fields.

- **Value**: The CSRF token (`loginToken`) changes on **every page load** and must be **extracted dynamically** for each login attempt.

#### Cookie Example (from HTTP response headers):
```

Set-Cookie: session=eyJ0b2tlbklEIjoiMzUyNTQ5ZjgxZDRhOTM5YjVlMTNlMjIzNmI0ZDlkOGEifQ.YSA-mQ.ZaKKsUnNsIb47sjlyux_LN8Qst0; HttpOnly; Path=/

```
  

- **Session Cookie**: The session identifier (`session`) also changes on each page load.
  
---
### 2. Detailed Macro Setup in Burp Suite

#### Step 1: Capture the Request to `/admin/login/`


- Open your browser and navigate to `http://10.10.191.224/admin/login/`.

- Ensure Burp Proxy is running and intercepting traffic.

- Capture the **GET request** to `/admin/login/` in Burp's HTTP history.

#### Step 2: Create a Macro

- Navigate to **Settings** (top-right corner of Burp Suite).

- Select the **Sessions** tab.

- Scroll down to **Macros** and click **Add**.

- From the HTTP history, select the **GET /admin/login/** request.

- Click **OK** to proceed.

- Name the macro (e.g., "Fetch Login Token and Session").

  
#### Step 3: Configure Extraction Rules


- After selecting the request for the macro, Burp will prompt you to define what values to extract:

- **loginToken**:

- Extract from the **response body** using a regular expression.

- Example Regex: `<input type="hidden" name="loginToken" value="([a-f0-9]+)">`

- **session**:

- Extract from the **Set-Cookie** header.

- Select the `session` cookie from the available headers.

- Confirm the extraction rules and save the macro.

---
### 3. Session Handling Rule (Link Macro to Intruder)

#### Step 1: Create Session Handling Rule

  
- Stay in the **Sessions** tab.

- Scroll up to **Session Handling Rules** and click **Add**.

- **Details Tab**:

- Enter a descriptive name (e.g., "Update CSRF Token and Session for Intruder").

#### Step 2: Define Scope

- Switch to the **Scope** tab:

- **Tools Scope**: Only select **Intruder**.

- **URL Scope**: Either set to **Use suite scope** (if you've configured it) or **Use custom scope**:

- Add `http://10.10.191.224/` to the scope.

#### Step 3: Define Rule Actions

- Return to the **Details** tab.

- Under **Rule Actions**, click **Add** and select **Run a macro**.

- Choose the macro created earlier ("Fetch Login Token and Session").

#### Step 4: Limit Parameter and Cookie Updates

- Configure **which values the macro updates**:

- **Update only the following parameters and headers**:

- Click **Edit** and add `loginToken`.

- **Update only the following cookies**:

- Click **Edit** and add `session`.

- Click **OK** to save the session handling rule.

---

### 4. Intruder Configuration and Attack

#### Step 1: Configure Intruder


- Send a **POST login request** to Intruder.

- **Attack Type**: Set to **Pitchfork**.

- **Positions**:

- Select only the **username** and **password** fields.

- Clear all other positions (CSRF token and session will be handled by the macro).

#### Step 2: Load Payloads

- In the **Payloads** tab:

- Use your **username** wordlist for Payload Set 1.

- Use your **password** wordlist for Payload Set 2.


#### Step 3: Start the Attack


- Begin the attack.

- The macro runs **before each request**, fetching a fresh **loginToken** and **session cookie**.

- Intruder uses these fresh values in each login attempt.


---
### 5. Analyze Responses


- **Expected Response**: Each request returns a **302 Redirect** (indicating login processing).

- **Identify Success**:

- Sort responses by **length**.

- Successful login attempts usually have a **shorter redirect response** (lacking the error message).

---

### Summary:

1. **GET /admin/login/** request fetches fresh **loginToken** and **session cookie**.

2. Macro **extracts** these values and **updates Intruder requests**.

3. Allows brute-forcing against CSRF-protected login forms.

4. Analyze **response lengths** to identify successful logins.

This process is critical for bypassing **anti-automation defenses** in **CSRF-protected** login forms and enables efficient brute-forcing using **Burp Suite Intruder**.