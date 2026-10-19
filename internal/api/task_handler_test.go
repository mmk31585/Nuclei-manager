package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/mmk31585/Nuclei-manager/internal/domain"
)

type fakeTaskRepo struct {
	mu    sync.Mutex
	tasks map[uint]*domain.Task
	next  uint
}

func newFakeTaskRepo() *fakeTaskRepo {
	return &fakeTaskRepo{tasks: map[uint]*domain.Task{}, next: 1}
}

func (r *fakeTaskRepo) Create(_ context.Context, t *domain.Task) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t.ID == 0 {
		t.ID = r.next
		r.next++
	}
	cp := *t
	r.tasks[t.ID] = &cp
	return nil
}

func (r *fakeTaskRepo) Get(_ context.Context, id uint) (*domain.Task, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.tasks[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	cp := *t
	return &cp, nil
}

func (r *fakeTaskRepo) List(_ context.Context) ([]domain.Task, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]domain.Task, 0, len(r.tasks))
	for _, t := range r.tasks {
		out = append(out, *t)
	}
	return out, nil
}

func (r *fakeTaskRepo) Update(_ context.Context, t *domain.Task) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.tasks[t.ID]; !ok {
		return domain.ErrNotFound
	}
	cp := *t
	r.tasks[t.ID] = &cp
	return nil
}

func (r *fakeTaskRepo) Delete(_ context.Context, id uint) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.tasks[id]; !ok {
		return domain.ErrNotFound
	}
	delete(r.tasks, id)
	return nil
}

type fakeTargetRepo struct {
	mu      sync.Mutex
	targets map[uint]*domain.Target
}

func newFakeTargetRepo() *fakeTargetRepo {
	return &fakeTargetRepo{targets: map[uint]*domain.Target{}}
}

func (r *fakeTargetRepo) seed(t *domain.Target) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t.ID == 0 {
		t.ID = uint(len(r.targets) + 1)
	}
	cp := *t
	r.targets[t.ID] = &cp
}

func (r *fakeTargetRepo) Create(_ context.Context, t *domain.Target) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t.ID == 0 {
		t.ID = uint(len(r.targets) + 1)
	}
	cp := *t
	r.targets[t.ID] = &cp
	return nil
}

func (r *fakeTargetRepo) Get(_ context.Context, id uint) (*domain.Target, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.targets[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	cp := *t
	return &cp, nil
}

func (r *fakeTargetRepo) List(_ context.Context) ([]domain.Target, error) { return nil, nil }
func (r *fakeTargetRepo) Update(_ context.Context, t *domain.Target) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.targets[t.ID] = t
	return nil
}
func (r *fakeTargetRepo) Delete(_ context.Context, id uint) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.targets, id)
	return nil
}

type fakeProfileRepo struct {
	mu       sync.Mutex
	profiles map[uint]*domain.Profile
}

func newFakeProfileRepo() *fakeProfileRepo {
	return &fakeProfileRepo{profiles: map[uint]*domain.Profile{}}
}

func (r *fakeProfileRepo) seed(p *domain.Profile) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if p.ID == 0 {
		p.ID = uint(len(r.profiles) + 1)
	}
	cp := *p
	r.profiles[p.ID] = &cp
}

func (r *fakeProfileRepo) Create(_ context.Context, p *domain.Profile) error { return nil }
func (r *fakeProfileRepo) Get(_ context.Context, id uint) (*domain.Profile, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.profiles[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	cp := *p
	return &cp, nil
}
func (r *fakeProfileRepo) List(_ context.Context) ([]domain.Profile, error)  { return nil, nil }
func (r *fakeProfileRepo) Update(_ context.Context, p *domain.Profile) error { return nil }
func (r *fakeProfileRepo) Delete(_ context.Context, id uint) error           { return nil }

func newTaskRouter(t *testing.T) (*gin.Engine, *fakeTaskRepo, *fakeTargetRepo, *fakeProfileRepo) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	tr := newFakeTaskRepo()
	tg := newFakeTargetRepo()
	pg := newFakeProfileRepo()
	tg.seed(&domain.Target{ID: 1, Name: "tgt", Hosts: []string{"http://example.com"}})
	pg.seed(&domain.Profile{ID: 1, Name: "quick", Severity: []string{"medium"}})
	h := NewTaskHandler(tr, tg, pg)
	r := gin.New()
	g := r.Group("/api/v1")
	h.Register(g)
	return r, tr, tg, pg
}

func doJSON(t *testing.T, r *gin.Engine, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestTaskHandlerCreateAndList(t *testing.T) {
	r, _, _, _ := newTaskRouter(t)
	w := doJSON(t, r, "POST", "/api/v1/tasks", map[string]any{
		"name": "task1", "target_id": 1, "profile_id": 1,
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body = %s", w.Code, w.Body.String())
	}
	var created domain.Task
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.ID == 0 {
		t.Fatal("expected id")
	}
	w = doJSON(t, r, "GET", "/api/v1/tasks", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list status = %d", w.Code)
	}
	var list []domain.Task
	json.Unmarshal(w.Body.Bytes(), &list)
	if len(list) != 1 {
		t.Fatalf("list len = %d", len(list))
	}
}

func TestTaskHandlerCreateValidation(t *testing.T) {
	r, _, _, _ := newTaskRouter(t)
	cases := []struct {
		body map[string]any
		code int
	}{
		{map[string]any{"name": "", "target_id": 1, "profile_id": 1}, http.StatusBadRequest},
		{map[string]any{"name": "x", "target_id": 99, "profile_id": 1}, http.StatusBadRequest},
		{map[string]any{"name": "x", "target_id": 1, "profile_id": 99}, http.StatusBadRequest},
	}
	for _, tc := range cases {
		w := doJSON(t, r, "POST", "/api/v1/tasks", tc.body)
		if w.Code != tc.code {
			t.Errorf("body %v: status = %d, want %d: %s", tc.body, w.Code, tc.code, w.Body.String())
		}
	}
}

func TestTaskHandlerGetUpdateDelete(t *testing.T) {
	r, _, _, _ := newTaskRouter(t)
	w := doJSON(t, r, "POST", "/api/v1/tasks", map[string]any{
		"name": "task1", "target_id": 1, "profile_id": 1,
	})
	var created domain.Task
	json.Unmarshal(w.Body.Bytes(), &created)

	w = doJSON(t, r, "GET", fmt.Sprintf("/api/v1/tasks/%d", created.ID), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("get status = %d", w.Code)
	}
	w = doJSON(t, r, "PUT", fmt.Sprintf("/api/v1/tasks/%d", created.ID), map[string]any{
		"name": "task2", "target_id": 1, "profile_id": 1,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("update status = %d: %s", w.Code, w.Body.String())
	}
	var updated domain.Task
	json.Unmarshal(w.Body.Bytes(), &updated)
	if updated.Name != "task2" {
		t.Errorf("name not updated")
	}
	req := httptest.NewRequest("DELETE", fmt.Sprintf("/api/v1/tasks/%d", created.ID), nil)
	wr := httptest.NewRecorder()
	r.ServeHTTP(wr, req)
	if wr.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d", wr.Code)
	}
	w = doJSON(t, r, "GET", fmt.Sprintf("/api/v1/tasks/%d", created.ID), nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("get after delete status = %d", w.Code)
	}
}

func TestTaskHandlerBadID(t *testing.T) {
	r, _, _, _ := newTaskRouter(t)
	w := doJSON(t, r, "GET", "/api/v1/tasks/abc", nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d", w.Code)
	}
}
