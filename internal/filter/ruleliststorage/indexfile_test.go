package ruleliststorage_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/filtertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/ruleliststorage"
	"github.com/stretchr/testify/require"
)

func TestIndexFile(t *testing.T) {
	t.Parallel()

	idxFile, err := os.CreateTemp(t.TempDir(), filepath.Base(t.Name()))
	require.NoError(t, err)

	_, err = idxFile.Write(newIndexData(t))
	require.NoError(t, err)
	require.NoError(t, idxFile.Close())

	f := ruleliststorage.NewIndexFile(&ruleliststorage.IndexFileConfig{
		Logger:   filtertest.Logger,
		ErrColl:  agdtest.NewErrorCollector(),
		FilePath: idxFile.Name(),
	})

	assertIndexData(t, f)
}
