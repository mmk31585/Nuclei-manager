package store

import (
	"errors"
	"fmt"

	mysqldriver "github.com/go-sql-driver/mysql"
	"gorm.io/gorm"

	"github.com/mmk31585/Nuclei-manager/internal/domain"
)

// mapErr converts driver errors to domain errors. Unknown errors pass through.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return domain.ErrNotFound
	}
	var me *mysqldriver.MySQLError
	if errors.As(err, &me) && me.Number == 1062 {
		return fmt.Errorf("%w: a record with the same unique value already exists", domain.ErrConflict)
	}
	return err
}
