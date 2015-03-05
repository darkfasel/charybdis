/*
 * Charybdis: an advanced ircd
 * ip_cloaking_darkfasel.c: provide user hostname sha512 cloaking
 *
 * Written originally by nenolod and Elisabeth, altered to use for darkfasel by argv in 2015
 * 
 */

#include "stdinc.h"
#include "modules.h"
#include "hook.h"
#include "client.h"
#include "ircd.h"
#include "send.h"
#include "hash.h"
#include "s_conf.h"
#include "s_user.h"
#include "s_serv.h"
#include "numeric.h"
#include "newconf.h"

static int
_modinit(void)
{
	/* add the usermode to the available slot */
	user_modes['x'] = find_umode_slot();
	construct_umodebuf();

	return 0;
}

static void
_moddeinit(void)
{
	/* disable the umode and remove it from the available list */
	user_modes['x'] = 0;
	construct_umodebuf();
}

static void check_umode_change(void *data);
static void check_new_user(void *data);
mapi_hfn_list_av1 ip_cloaking_darkfasel_hfnlist[] = {
	{ "umode_changed", (hookfn) check_umode_change },
	{ "new_local_user", (hookfn) check_new_user },
	{ NULL, NULL }
};

DECLARE_MODULE_AV1(ip_cloaking_darkfasel, _modinit, _moddeinit, NULL, NULL,
			ip_cloaking_darkfasel_hfnlist, "$Revision: 0042 $");

static void
distribute_hostchange(struct Client *client_p, char *newhost)
{
	if (newhost != client_p->orighost)
		sendto_one_numeric(client_p, RPL_HOSTHIDDEN, "%s :is now your hidden host",
			newhost);
	else
		sendto_one_numeric(client_p, RPL_HOSTHIDDEN, "%s :hostname reset",
			newhost);

	sendto_server(NULL, NULL,
		CAP_EUID | CAP_TS6, NOCAPS, ":%s CHGHOST %s :%s",
		use_id(&me), use_id(client_p), newhost);
	sendto_server(NULL, NULL,
		CAP_TS6, CAP_EUID, ":%s ENCAP * CHGHOST %s :%s",
		use_id(&me), use_id(client_p), newhost);

	change_nick_user_host(client_p, client_p->name, client_p->username, newhost, 0, "Changing host");

	if (newhost != client_p->orighost)
		SetDynSpoof(client_p);
	else
		ClearDynSpoof(client_p);
}

static void
do_address_cloak(const char *inbuf, char *outbuf)
{
  /* sha512 */
  char algorithm[4] = "$6$";

  /* key */
  char *key = "%fn0rd$m0m0+fp";

  char salt[64];
  sprintf(salt, "%s%s", algorithm, key);

  /* check default value */
  if (!strcmp(key, "fnord"))
  {

    /* seed chars */
    const char *const chars =
      "0123456789ABCDEFGHIJKLMNOPQRSTUV"
      "WXYZabcdefghijklmnopqrstuvwxyz/.";

    /* not very random seed */
    unsigned long seed[2];
    seed[0] = time(NULL);
    seed[1] = getpid() ^ (seed[0] >> 14 & 0x30000);

    /* printable characters */
    int salt_i;
    for (salt_i = 0; salt_i < 5; salt_i++)
      salt[3+salt_i] = chars[(seed[salt_i/5] >> (salt_i%5)*6) & 0x3f];
  }

  /* encrypt */
  char *hash = rb_crypt(inbuf, salt);

  /* replace not usable characters */
  int replace_i;
  for (replace_i=0; hash[replace_i]!= '\0'; replace_i++) {

    if ((hash[replace_i]=='/') || (hash[replace_i]=='$')) {

      hash[replace_i] = '.';
    }
  }

  /* hide characters */
  hash[strlen(hash)-17] = '\0';
  hash = hash + 46;

  /* beam me up */
  rb_strlcpy(outbuf, hash, HOSTLEN + 1);
}

static void
check_umode_change(void *vdata)
{
	hook_data_umode_changed *data = (hook_data_umode_changed *)vdata;
	struct Client *source_p = data->client;

	if (!MyClient(source_p))
		return;

	/* didn't change +h umode, we don't need to do anything */
	if (!((data->oldumodes ^ source_p->umodes) & user_modes['x']))
		return;

	if (source_p->umodes & user_modes['x'])
	{
		if (IsIPSpoof(source_p) || source_p->localClient->mangledhost == NULL || (IsDynSpoof(source_p) && strcmp(source_p->host, source_p->localClient->mangledhost)))
		{
			source_p->umodes &= ~user_modes['x'];
			return;
		}
		if (strcmp(source_p->host, source_p->localClient->mangledhost))
		{
			distribute_hostchange(source_p, source_p->localClient->mangledhost);
		}
		else /* not really nice, but we need to send this numeric here */
			sendto_one_numeric(source_p, RPL_HOSTHIDDEN, "%s :is now your hidden host",
				source_p->host);
	}
	else if (!(source_p->umodes & user_modes['x']))
	{
		if (source_p->localClient->mangledhost != NULL &&
				!strcmp(source_p->host, source_p->localClient->mangledhost))
		{
			distribute_hostchange(source_p, source_p->orighost);
		}
	}
}

static void
check_new_user(void *vdata)
{
	struct Client *source_p = (void *)vdata;
	if (IsIPSpoof(source_p))
	{
		source_p->umodes &= ~user_modes['x'];
		return;
	}
	source_p->localClient->mangledhost = rb_malloc(HOSTLEN + 1);
	do_address_cloak(source_p->orighost, source_p->localClient->mangledhost);
	if (IsDynSpoof(source_p))
		source_p->umodes &= ~user_modes['x'];
	if (source_p->umodes & user_modes['x'])
	{
		if (irccmp(source_p->host, source_p->orighost))
			SetDynSpoof(source_p);
	}
}
