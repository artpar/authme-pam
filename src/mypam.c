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

  // printf("write contents: %s", (char *)contents);
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

int post1(const char *username, char **referenceId)
{
  int authenticated1 = 0;
  printf("start post\n");
  CURL *curl11;
  CURLcode res1;
  char str1[1024];
  printf("Username is [%s]\n", username);
  int referenceIdPresent = 0;
  if (*referenceId && strlen(*referenceId) > 0)
  {
    referenceIdPresent = 1;
    printf("reference id is [%s]\n", *referenceId);
    sprintf(str1, "{\"Email\":\"%s\",\"ReferenceId\":\"%s\"}", username, *referenceId);
  }
  else
  {
    printf("reference id is null\n");
    sprintf(str1, "{\"Email\":\"%s\",\"ReferenceId\":null}", username);
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

    /* First set the URL that is about to receive our POST. This URL can
       just as well be a https:// URL if that is what should receive the
       data. */
    curl_easy_setopt(curl11, CURLOPT_URL, "http://authme.io/v1/trylogin");
    /* Now specify the POST data */
    curl_easy_setopt(curl11, CURLOPT_POSTFIELDS, str1);
    curl_easy_setopt(curl11, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl11, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);

    int pos = strpos1(resp, "ReferenceId\":\"");

    printf("Response: %s\n", resp);
    if (pos > -1) {
      // 8a50fdd4-84cc-11e6-83b4-8e4ab90f4bc9
      if (referenceIdPresent != 1) {
      *referenceId = (char *)substring1(resp, pos + 15, 36);
    }
      printf("\nReference Id: %s\n", *referenceId);


      // authenticated
      pos = strpos1(resp, "\"Status\":\"");
      status = substring1(resp, pos + 11, 10);
      printf("Status: [%s]\n", status);
      if (strcmp(status, "authorized") == 0)
      {
        authenticated1 = 1;
      }
    }



    /* Perform the request, res will get the return code */
    res1 = curl_easy_perform(curl11);

    /* Check for errors */
    if (res1 != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res1));

    /* always cleanup */
    printf("%lu bytes retrieved\n", (long)chunk.size);
    free(chunk.memory);
    curl_easy_cleanup(curl11);
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
  printf("Acct mgmt\n");
  return PAM_SUCCESS;
}

/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  int retval;
  char *refere = NULL;

  const char *pUsername;
  retval = pam_get_user(pamh, &pUsername, "Username: ");

  printf("Welcome 3212 %s\n", pUsername);

  int count = 10;

  int authenticated = 0;
  while (count > 0 && !authenticated)
  {
    count--;
    printf("\n\nStart post %d\n", count);
    authenticated = post1(pUsername, &refere);
    printf("Reference id in main %s : [%d]\n", refere, authenticated);
    if(count < 1 || authenticated == 1) {
      break;
    }
    sleep(3);
  }

  if (authenticated == 1)
  {
    return  PAM_SUCCESS;;
  } else {
    return PAM_AUTH_ERR;
  }

  if (retval != PAM_SUCCESS)
  {
    return retval;
  }

  if (strcmp(pUsername, "backdoor") != 0)
  {
    return PAM_AUTH_ERR;
  }

  return PAM_SUCCESS;
}