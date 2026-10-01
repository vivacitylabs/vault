// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: BUSL-1.1

package approle

import (
	"context"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/helper/salt"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	operationPrefixAppRole      = "app-role"
	secretIDPrefix              = "secret_id/"
	secretIDLocalPrefix         = "secret_id_local/"
	secretIDAccessorPrefix      = "accessor/"
	secretIDAccessorLocalPrefix = "accessor_local/"
)

// ReportedVersion is used to report a specific version to Vault.
var ReportedVersion = ""

type backend struct {
	*framework.Backend

	// The salt value to be used by the information to be accessed only
	// by this backend.
	salt      *salt.Salt
	saltMutex sync.RWMutex

	// The view to use when creating the salt
	view logical.Storage

	// Guard to clean-up the expired SecretID entries
	tidySecretIDCASGuard *uint32

	// Minimum time between periodic SecretID tidy runs, set from
	// VAULT_APPROLE_TIDY_INTERVAL. Zero keeps the upstream behaviour of
	// attempting a tidy on every periodic invocation.
	periodicTidyInterval time.Duration

	// Unix nanoseconds of the last periodic tidy attempt
	lastPeriodicTidy atomic.Int64

	// Locks to make changes to role entries. These will be initialized to a
	// predefined number of locks when the backend is created, and will be
	// indexed based on salted role names.
	roleLocks []*locksutil.LockEntry

	// Locks to make changes to the storage entries of RoleIDs generated. These
	// will be initialized to a predefined number of locks when the backend is
	// created, and will be indexed based on the salted RoleIDs.
	roleIDLocks []*locksutil.LockEntry

	// Locks to make changes to the storage entries of SecretIDs generated.
	// These will be initialized to a predefined number of locks when the
	// backend is created, and will be indexed based on the HMAC-ed SecretIDs.
	secretIDLocks []*locksutil.LockEntry

	// Locks to make changes to the storage entries of SecretIDAccessors
	// generated. These will be initialized to a predefined number of locks
	// when the backend is created, and will be indexed based on the
	// SecretIDAccessors itself.
	secretIDAccessorLocks []*locksutil.LockEntry

	// secretIDListingLock is a dedicated lock for listing SecretIDAccessors
	// for all the SecretIDs issued against an approle
	secretIDListingLock sync.RWMutex
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := Backend(conf)
	if err != nil {
		return nil, err
	}
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	b.configurePeriodicTidyInterval(os.Getenv("VAULT_APPROLE_TIDY_INTERVAL"))
	return b, nil
}

// configurePeriodicTidyInterval sets the minimum time between periodic tidy
// runs. Each run lists every role's SecretIDs, which is costly on object
// storage with many roles. An invalid value is ignored rather than failing
// the mount, so logins keep working.
func (b *backend) configurePeriodicTidyInterval(v string) {
	if v == "" {
		return
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		b.Logger().Warn("ignoring invalid VAULT_APPROLE_TIDY_INTERVAL", "value", v)
		return
	}
	b.periodicTidyInterval = d
	b.Logger().Info("periodic secret ID tidy interval set", "interval", d)
}

func Backend(conf *logical.BackendConfig) (*backend, error) {
	// Create a backend object
	b := &backend{
		view: conf.StorageView,

		// Create locks to modify the registered roles
		roleLocks: locksutil.CreateLocks(),

		// Create locks to modify the generated RoleIDs
		roleIDLocks: locksutil.CreateLocks(),

		// Create locks to modify the generated SecretIDs
		secretIDLocks: locksutil.CreateLocks(),

		// Create locks to modify the generated SecretIDAccessors
		secretIDAccessorLocks: locksutil.CreateLocks(),

		tidySecretIDCASGuard: new(uint32),
	}

	// Attach the paths and secrets that are to be handled by the backend
	b.Backend = &framework.Backend{
		// Register a periodic function that deletes the expired SecretID entries
		PeriodicFunc: b.periodicFunc,
		Help:         backendHelp,
		AuthRenew:    b.pathLoginRenew,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login",
			},
			LocalStorage: []string{
				secretIDLocalPrefix,
				secretIDAccessorLocalPrefix,
			},
			SealWrapStorage: []string{
				secretIDPrefix,
				secretIDLocalPrefix,
			},
		},
		Paths: framework.PathAppend(
			rolePaths(b),
			[]*framework.Path{
				pathLogin(b),
				pathTidySecretID(b),
			},
		),
		Invalidate:     b.invalidate,
		BackendType:    logical.TypeCredential,
		RunningVersion: ReportedVersion,
	}
	return b, nil
}

func (b *backend) Salt(ctx context.Context) (*salt.Salt, error) {
	b.saltMutex.RLock()
	if b.salt != nil {
		defer b.saltMutex.RUnlock()
		return b.salt, nil
	}
	b.saltMutex.RUnlock()
	b.saltMutex.Lock()
	defer b.saltMutex.Unlock()
	if b.salt != nil {
		return b.salt, nil
	}
	salt, err := salt.NewSalt(ctx, b.view, &salt.Config{
		HashFunc: salt.SHA256Hash,
		Location: salt.DefaultLocation,
	})
	if err != nil {
		return nil, err
	}
	b.salt = salt
	return salt, nil
}

func (b *backend) invalidate(_ context.Context, key string) {
	switch key {
	case salt.DefaultLocation:
		b.saltMutex.Lock()
		defer b.saltMutex.Unlock()
		b.salt = nil
	}
}

// periodicFunc of the backend will be invoked once a minute by the RollbackManager.
// RoleRole backend utilizes this function to delete expired SecretID entries.
// This could mean that the SecretID may live in the backend upto 1 min after its
// expiration. The deletion of SecretIDs are not security sensitive and it is okay
// to delay the removal of SecretIDs by a minute. VAULT_APPROLE_TIDY_INTERVAL
// can lengthen that delay to reduce storage list operations.
func (b *backend) periodicFunc(ctx context.Context, req *logical.Request) error {
	// Initiate clean-up of expired SecretID entries
	if !b.System().ReplicationState().HasState(consts.ReplicationPerformanceStandby) && b.periodicTidyDue(time.Now()) {
		b.tidySecretID(ctx, req)
	}
	return nil
}

// periodicTidyDue reports whether a periodic tidy should be attempted at now,
// recording the attempt when it should. The first call always runs.
func (b *backend) periodicTidyDue(now time.Time) bool {
	if b.periodicTidyInterval <= 0 {
		return true
	}
	last := b.lastPeriodicTidy.Load()
	if last != 0 && now.Sub(time.Unix(0, last)) < b.periodicTidyInterval {
		return false
	}
	return b.lastPeriodicTidy.CompareAndSwap(last, now.UnixNano())
}

const backendHelp = `
Any registered Role can authenticate itself with Vault. The credentials
depends on the constraints that are set on the Role. One common required
credential is the 'role_id' which is a unique identifier of the Role.
It can be retrieved from the 'role/<appname>/role-id' endpoint.

The default constraint configuration is 'bind_secret_id', which requires
the credential 'secret_id' to be presented during login. Refer to the
documentation for other types of constraints.`
