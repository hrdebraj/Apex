# Contributing to Apex C2

## Branch Workflow

**Direct merges into `main` are not allowed.** All changes require:

1. Work on a **testing branch** (e.g. your feature or testing branch—never commit directly to `main`)
2. A **pull request** from your testing branch targeting `main`
3. At least **one approval** from a collaborator
4. Merge only after the review is approved

### Quick Steps

```bash
git checkout <your-testing-branch> && git pull origin <your-testing-branch>
# ... make changes ...
git add . && git commit -m "Your message"
git push origin <your-testing-branch>
```

Then open a PR on GitHub (**your testing branch → main**) and request a review.

---


