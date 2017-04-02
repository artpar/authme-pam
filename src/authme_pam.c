#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include <curl/curl.h>
#include <unistd.h>

int strpos1(char *haystack, char *needle)
{
  char *p = strstr(haystack, needle);
  if (p)
    return p - haystack;
  return -1;
}

/*C substring function: It returns a pointer to the substring */

char *substring1(char *string, int position, int length)
{
  char *pointer;
  int c;

  pointer = malloc(length + 1);

  if (pointer == NULL)
  {
    printf("Unable to allocate memory.\n");
    exit(1);
  }

  for (c = 0; c < length; c++)
  {
    *(pointer + c) = *(string + position - 1);
    string++;
  }

  *(pointer + c) = '\0';

  return pointer;
}

struct MemoryStruct
{
  char *memory;
  size_t size;
};

char resp[1024];

static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  memcpy(resp, contents, realsize);

  // printf("write contents: [%s] == [%s]\n", (char *)contents, resp);
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;

  mem->memory = realloc(mem->memory, mem->size + realsize + 1);
  if (mem->memory == NULL)
  {
    /* out of memory! */
    printf("not enough memory (realloc returned NULL)\n");
    return 0;
  }

  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;

  return realsize;
}

int post1(const char *username, char **referenceId, const char *apikey, const char *apisecret, const char *baseurl)
{
  int authenticated1 = 0;
  // printf("start post\n");
  CURL *curl11;
  CURLcode res1;
  char str1[1024];
  char url[200];
  // printf("Username is [%s]\n", username);
  int referenceIdPresent = 0;
  if (*referenceId && strlen(*referenceId) > 0)
  {
    referenceIdPresent = 1;
    // printf("reference id is [%s]\n", *referenceId);
    sprintf(str1, "{\"UserIdentifier\":\"%s\",\"ReferenceId\":\"%s\"}", username, *referenceId);
    sprintf(url, "https://api.authme.authme.host/order/%s", *referenceId);
  }
  else
  {
    // printf("reference id is null\n");
    sprintf(str1, "{\"UserIdentifier\":\"%s\",\"ReferenceId\":null}", username);
    sprintf(url, "https://api.authme.authme.host/order");
  }

  /* In windows, this will init the winsock stuff */
  curl_global_init(CURL_GLOBAL_ALL);

  /* get a curl handle */
  curl11 = curl_easy_init();
  if (curl11)
  {
    struct MemoryStruct chunk;

    chunk.memory = malloc(1); /* will be grown as needed by the realloc above */
    chunk.size = 0;           /* no data at this point */
    char *status;

    struct curl_slist *headerChunk = NULL;

    /* Remove a header curl would otherwise add by itself */
    headerChunk = curl_slist_append(headerChunk, "Accept:");

    /* Add a custom header */
    char headerValue[1024];
    sprintf(headerValue, "X-Api-Key: %s", apikey);
    headerChunk = curl_slist_append(headerChunk, headerValue);

    /* set our custom set of headers */
    curl_easy_setopt(curl11, CURLOPT_HTTPHEADER, headerChunk);

    /* First set the URL that is about to receive our POST. This URL can
       just as well be a https:// URL if that is what should receive the
       data. */
    curl_easy_setopt(curl11, CURLOPT_URL, url);
    /* Now specify the POST data */
    // printf("Post data [%s]\n", str1);
    curl_easy_setopt(curl11, CURLOPT_POSTFIELDS, str1);
    curl_easy_setopt(curl11, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl11, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);

    /* Perform the request, res will get the return code */
    res1 = curl_easy_perform(curl11);

    /* Check for errors */
    if (res1 != CURLE_OK)
    {
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res1));
    }

    int pos = strpos1(resp, "ReferenceId\":\"");

    // printf("Response: [%s]\n", resp);
    if (pos > -1)
    {
      // 8a50fdd4-84cc-11e6-83b4-8e4ab90f4bc9
      if (referenceIdPresent != 1)
      {
        *referenceId = (char *)substring1(resp, pos + 15, 36);
      }
      // printf("\nReference Id: %s\n", *referenceId);

      // authenticated
      pos = strpos1(resp, "\"Status\":\"");
      status = substring1(resp, pos + 11, 10);
      // printf("Status: [%s]\n", status);
      if (strcmp(status, "authorized") == 0)
      {
        authenticated1 = 1;
      } else if (strcmp(status, "no_account") == 0)
      {
        return -1;
      } else if (strcmp(status, "rejected\",") == 0) {
        return -3;
      } else if (strcmp(status, "auth_initi") != 0) {
        return -2;
      }
    }

    /* always cleanup */
    // printf("%lu bytes retrieved\n", (long)chunk.size);
    free(chunk.memory);
    curl_easy_cleanup(curl11);
    curl_slist_free_all(headerChunk);
  }
  curl_global_cleanup();
  return authenticated1;
}

/* expected hook */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  // printf("Acct mgmt\n");
  return PAM_SUCCESS;
}

/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{

  int retval;
  char *refere = NULL;

  int gotApiKey = 0;
  int gotApiSecret = 0;
  int gotEndPoint = 0;
  int gotDomain = 0;
  printf("start\n");
  /* retrieving parameters */
  char api_key[256];
  char api_secret[256];
  char base_url[256];
  char domain[256];
  for (int i = 0; i < argc; i++)
  {
    // printf("Check arg: %s\n", argv[i]);

    if (strncmp(argv[i], "apikey=", 7) == 0)
    {
      strncpy(api_key, argv[i] + 7, 256);
      // printf("ApiKey: %s\n", api_key);
      gotApiKey = 1;
    }
    else if (strncmp(argv[i], "apisecret=", 10) == 0)
    {
      strncpy(api_secret, argv[i] + 10, 256);
      // printf("ApiSecret: %s\n", api_secret);
      gotApiSecret = 1;
    }
    else if (strncmp(argv[i], "baseurl=", 8) == 0)
    {
      strncpy(base_url, argv[i] + 8, 256);
      // printf("Baseurl: %s\n", base_url);
      gotEndPoint = 1;
    }
    else if (strncmp(argv[i], "domain=", 7) == 0)
    {
      strncpy(domain, argv[i] + 7, 256);
      // printf("Domain: %s\n", domain);
      gotDomain = 1;
    }
  }
  if (gotApiKey == 0 || gotApiSecret == 0 || gotEndPoint == 0 || gotDomain == 0)
  {
    return PAM_AUTH_ERR;
  }

  const char *pUsername;
  char tempUsername[256];
  retval = pam_get_user(pamh, &pUsername, "Username: ");
  // tempUsername = pUsername;

  if (strcmp("root", pUsername) == 0) {
    return PAM_AUTH_ERR;
  }

  sprintf(tempUsername, "%s@%s", pUsername, domain);
  // if (strcmp("artpar", pUsername) == 0)
  // {
  //   tempUsername = "artpar@gmail.com";
  // } else if (strcmp("shardul", pUsername) == 0) {
  //   tempUsername = "developershardul@gmail.com";
  // } else {
  //   return PAM_AUTH_ERR;
  // }
  printf("Welcome %s, Please swipe on your mobile to login\n", tempUsername);

  int count = 10;

  int authenticated = 0;
  while (count > 0 && !authenticated)
  {
    count--;
    // printf("\n\nStart post %d\n", count);
    authenticated = post1(tempUsername, &refere, api_key, api_secret, base_url);
    // printf("Reference id in main %s : [%d]\n", refere, authenticated);
    if (count < 1 || authenticated == 1)
    {
      break;
    }

    if (authenticated == -1) {
      printf("Please install authme app to login via AuthMe: https://play.google.com/store/apps/details?id=io.authme.home\n");
      break;
    }

    if (authenticated == -2) {
      printf("Failed to initiate swipe\n.");
      break;
    }
    if (authenticated == -3) {
      printf("Swipe rejected, please try again.\n");
      break;
    }
    sleep(1.5);
  }

  if (authenticated == 1)
  {
    retval = PAM_SUCCESS;
  }
  else
  {
    retval = PAM_AUTH_ERR;
  }
  return retval;
}