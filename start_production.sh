
#!/bin/bash
echo "Starting AI Security Tester - Production Mode"
echo "============================================="

echo "Starting Backend Services..."
cd backend
python simple_async_main.py &
sleep 3
python pentest_api.py &
sleep 3

echo "Starting Frontend..."
cd ../frontend
npm run dev &

echo "============================================="
echo "AI Security Tester is running in Production Mode"
echo "Main Platform: http://localhost:3000"
echo "AI Orchestrator: http://localhost:3000/pentest"
echo "============================================="
wait
