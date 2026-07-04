/*
 * SPDX-FileCopyrightText: © 2017-2025 Istari Digital, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package edgraph

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dgraph-io/dgraph/v25/dql"
)

// A userid containing quote characters must not be able to add extra match
// values to the eq() function or open new query blocks in the reset-password
// upsert. eq(dgraph.xid, "a", "b") matches multiple users, so an unescaped
// userid would let a reset for one user also overwrite another user's password.
func TestResetPasswordQueryNoInjection(t *testing.T) {
	for _, userID := range []string{
		"alice",
		`alice", "bob`,
		`x")) { uid } all as var(func: has(dgraph.password`,
		`a"\`,
	} {
		q := resetPasswordQuery(userID)
		res, err := dql.ParseWithNeedVars(dql.Request{Str: q}, []string{"x"})
		require.NoErrorf(t, err, "query for %q must parse: %s", userID, q)
		require.Len(t, res.Query, 1, "userid %q altered the number of query blocks", userID)

		fn := res.Query[0].Func
		require.Equal(t, "eq", fn.Name)
		require.Equal(t, "dgraph.xid", fn.Attr)
		require.Lenf(t, fn.Args, 1, "userid %q injected extra eq() values: %v", userID, fn.Args)
		require.Equal(t, userID, fn.Args[0].Value)
	}
}
