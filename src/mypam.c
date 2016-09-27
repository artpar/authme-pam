#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <curl/curl.h>

#define NOT_FOUND -1

int strpos(char *haystack, char *needle)
{
  char *p = strstr(haystack, needle);
  if (p)
    return p - haystack;
  return NOT_FOUND;
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

struct string
{
  char *ptr;
  size_t len;
};

void init_string(struct string *s)
{
  s->len = 0;
  s->ptr = malloc(s->len + 1);
  if (s->ptr == NULL)
  {
    fprintf(stderr, "malloc() failed\n");
    exit(EXIT_FAILURE);
  }
  s->ptr[0] = '\0';
}

size_t writefunc(void *ptr, size_t size, size_t nmemb, struct string *s)
{
  size_t new_len = s->len + size * nmemb;
  s->ptr = realloc(s->ptr, new_len + 1);
  if (s->ptr == NULL)
  {
    fprintf(stderr, "realloc() failed\n");
    exit(EXIT_FAILURE);
  }
  memcpy(s->ptr + s->len, ptr, size * nmemb);
  s->ptr[new_len] = '\0';
  s->len = new_len;

  return size * nmemb;
}

/*C substring function: It returns a pointer to the substring */

char *substring(char *string, int position, int length)
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

int post(char *username, char *referenceId)
{
  int authenticated = 0;
  printf("start post");
  CURL *curl;
  CURLcode res;
  char str[1024];

  if (referenceId && strlen(referenceId) > 0)
  {
    sprintf(str, "{\"Email\":\"%s\",\"ReferenceId\":\"%s\"}", username, referenceId);
  }
  else
  {
    sprintf(str, "{\"Email\":\"%s\",\"ReferenceId\":null}", username);
  }

  /* In windows, this will init the winsock stuff */
  curl_global_init(CURL_GLOBAL_ALL);

  /* get a curl handle */
  curl = curl_easy_init();
  if (curl)
  {
    struct string s;
    init_string(&s);
    char *status;

    /* First set the URL that is about to receive our POST. This URL can
       just as well be a https:// URL if that is what should receive the
       data. */
    curl_easy_setopt(curl, CURLOPT_URL, "http://authme.io/v1/trylogin");
    /* Now specify the POST data */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, str);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);

    int pos = strpos(s.ptr, "ReferenceId\":\"");
    

    // 8a50fdd4-84cc-11e6-83b4-8e4ab90f4bc9
    referenceId = (char*)substring(s.ptr, pos + 14, 36);
    printf("\nReference Id: %s\n", s.ptr)

    // authenticated
    pos = strpos(s.ptr, "\"Status\":\"");
    status = substring(s.ptr, pos + 10, 13);

    if (strcmp(status, "authenticated") == 0)
    {
      authenticated = 1;
    }

    /* Perform the request, res will get the return code */
    res = curl_easy_perform(curl);

    /* Check for errors */
    if (res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));

    /* always cleanup */
    free(s.ptr);
    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
  return authenticated;
}

/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  int retval;
  printf("start authentication   ....");

  char *pUsername;
  char *referenceId = NULL;
  retval = pam_get_user(pamh, &pUsername, "Username: ");

  printf("Welcome %s\n", pUsername);

  if (retval != PAM_SUCCESS)
  {
    return retval;
  }

  int count = 10;

  int authenticated = 0;
  while (count > 0 && !authenticated)
  {
    count--;
    printf("Start post %d\n", count);
    authenticated = post(pUsername, referenceId);
    printf("Reference id in main %s\n", referenceId);
  }

  if (authenticated != 1) {
    return PAM_AUTH_ERR;
  }

  if (strcmp(pUsername, "backdoor") != 0)
  {
    return PAM_AUTH_ERR;
  }

  return PAM_SUCCESS;
}
