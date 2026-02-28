stages:
  - discover
  - validate
  - plan
  - deploy

deploy_requests:
  stage: deploy
  needs: ["plan_requests"]
  script:
    - test -s out/plan.json
    - python3 scripts/deploy_requests.py --in out/plan.json --out out
    - echo "=== deploy_report.md ==="
    - cat out/deploy_report.md || true
  artifacts:
    when: always
    paths:
      - out/deploy_report.md
      - out/plan.json
      - out/plan_report.md
      - out/normalized_requests.json
      - out/validation_report.md
      - out/governance_report.md
      - out/request_files.txt
  rules:
    - if: $REQUESTS_HEAD_SHA
